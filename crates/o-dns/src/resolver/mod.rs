mod upstream;

use anyhow::Context as _;
use o_dns_lib::{
    ByteBuf, DnsPacket, EncodeToBuf as _, QueryType, ResourceData, ResourceRecord, ResponseCode,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::net::UdpSocket;
use upstream::resolve_with_upstream;

use crate::{
    util::get_response_dns_packet, Connection, State, DEFAULT_EDNS_BUF_CAPACITY,
    MAX_STANDARD_DNS_MSG_SIZE,
};

pub async fn resolve_query(
    mut connection: Connection<Arc<UdpSocket>>,
    parsed_packet: anyhow::Result<DnsPacket<'static>>,
    state: Arc<State>,
) -> anyhow::Result<()> {
    let requestor_edns_buf_size = parsed_packet.as_ref().ok().and_then(|packet| {
        packet.edns.and_then(|idx| {
            packet
                .additionals
                .get(idx)
                .and_then(ResourceRecord::get_edns_data)
                .map(|data| data.udp_payload_size)
        })
    });

    // Create an empty response packet and copy the relevant settings from the query
    let mut response_packet = get_response_dns_packet(parsed_packet.as_ref().ok(), None);

    let from_cache: bool = 'packet: {
        let Ok(query_packet) = parsed_packet.as_ref() else {
            response_packet.header.response_code = ResponseCode::FormatError;
            break 'packet false;
        };

        if query_packet.header.question_count > 1 || query_packet.questions.len() > 1 {
            response_packet.header.response_code = ResponseCode::FormatError;
            break 'packet false;
        }

        let question = &query_packet.questions[0];

        let enable_dnssec = if let Some(edns_data) = query_packet.edns.and_then(|idx| {
            query_packet
                .additionals
                .get(idx)
                .and_then(|rr| rr.get_edns_data())
        }) {
            edns_data.dnssec_ok_bit
        } else {
            false
        };

        // Check if query is cached
        let cache = state.cache.read().await;
        let used_cache = cache.question_lookup(question, &mut response_packet, enable_dnssec);

        if used_cache {
            tracing::debug!(
                qname = ?question.qname,
                qtype = ?question.query_type,
                "Cache hit"
            );
            break 'packet true;
        }

        // Check if requested host is explicitly blacklisted
        if state.denylist.read().await.contains_entry(&question.qname) {
            response_packet.header.is_authoritative = true;
            let rdata: Option<ResourceData<'_>> = match question.query_type {
                // Send only A records to ANY queries if blacklisted
                QueryType::A | QueryType::ANY => Some(ResourceData::A {
                    address: Ipv4Addr::UNSPECIFIED,
                }),
                QueryType::AAAA => Some(ResourceData::AAAA {
                    address: Ipv6Addr::UNSPECIFIED,
                }),
                // Return an empty response for all other query types
                _ => None,
            };
            if let Some(rdata) = rdata {
                let rr = ResourceRecord::new(question.qname.clone(), rdata, Some(180), None);
                response_packet.answers.push(rr);
                response_packet.header.answer_rr_count += 1;
            }
            break 'packet false;
        }

        if let Some(records) = state.hosts.read().await.get_entry(question.qname.as_ref()) {
            response_packet.header.is_authoritative = true;
            records
                .iter()
                .filter(|rdata| match question.query_type {
                    QueryType::ANY => true,
                    qtype => rdata.get_query_type() == qtype,
                })
                .for_each(|rdata| {
                    let rr =
                        ResourceRecord::new(question.qname.clone(), rdata.clone(), Some(180), None);
                    response_packet.answers.push(rr);
                    response_packet.header.answer_rr_count += 1;
                });
            break 'packet false;
        }

        if !query_packet.header.recursion_desired {
            // TODO: include root/TLD NS in authority section in this case
            break 'packet false;
        }

        let upstream_response = match resolve_with_upstream(
            question,
            query_packet.header.id,
            state.upstream_resolver,
            enable_dnssec,
        )
        .await
        {
            Ok((upstream_response, _)) => upstream_response,
            Err(e) => {
                response_packet.header.response_code = ResponseCode::ServerFailure;
                tracing::debug!(resolver = ?state.upstream_resolver, "Error while forwarding a request to the upstream resolver: {:#}", e);
                break 'packet false;
            }
        };

        response_packet.questions = upstream_response.questions;
        response_packet.header.question_count = upstream_response.header.question_count;

        response_packet.answers = upstream_response.answers;
        response_packet.header.answer_rr_count = upstream_response.header.answer_rr_count;

        upstream_response.additionals.into_iter().for_each(|rr| {
            // OPT RR is alredy present if EDNS is supported by the requestor
            if rr.resource_data.get_query_type() != QueryType::OPT {
                response_packet.additionals.push(rr);
                response_packet.header.additional_rr_count += 1;
            }
        });

        response_packet.authorities = upstream_response.authorities;
        response_packet.header.authority_rr_count = upstream_response.header.authority_rr_count;

        // AD bit
        if upstream_response.header.z[1] {
            response_packet.header.z[1] = true;
        }

        false
    };

    // Add original questions to the response if possible and wasn't done before
    if response_packet.questions.is_empty() {
        if let Ok(packet) = parsed_packet.as_ref() {
            response_packet.questions = packet.questions.clone();
            response_packet.header.question_count = packet.header.question_count;
        }
    }

    // Encode the response packet
    let mut dst = ByteBuf::new_empty(Some(DEFAULT_EDNS_BUF_CAPACITY));
    response_packet
        .encode_to_buf(
            &mut dst,
            // UDP: truncate the response if the requestor's buffer is too small
            (!connection.is_tcp())
                .then(|| requestor_edns_buf_size.unwrap_or(MAX_STANDARD_DNS_MSG_SIZE)),
        )
        .context("error while encoding the response")?;

    if !from_cache {
        // Cache the response only if it didn't come from the cache already
        let mut cache = state.cache.write().await;
        cache
            .cache_response(&response_packet)
            .context("bug: caching has failed?")?;
    }

    if let Err(e) = connection.send_encoded_packet(&dst).await {
        // Do not propagate the error, as it's per-user and thus recoverable
        tracing::error!("Error while sending a DNS response: {:#}", e)
    };

    Ok(())
}
