mod upstream;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::Context as _;
use o_dns_lib::{
    ByteBuf, DnsPacket, EncodeToBuf as _, QueryType, Question, ResourceData, ResourceRecord, ResponseCode,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Instant;
use upstream::resolve_with_upstream;

use crate::db::QueryLog;
use crate::hosts::ListEntryKind;
use crate::util::get_response_dns_packet;
use crate::{Connection, State, DEFAULT_EDNS_BUF_CAPACITY, MAX_STANDARD_DNS_MSG_SIZE};

#[derive(Debug, Clone, Copy)]
pub enum ResponseSource {
    Denylist,
    Allowlist,
    Cache,
    NoRecurse,
    Upstream,
}

pub struct Resolver {
    state: Arc<State>,
    log_tx: UnboundedSender<QueryLog>,
}
impl Resolver {
    pub fn new(state: State, log_tx: UnboundedSender<QueryLog>) -> Self {
        Resolver {
            state: Arc::new(state),
            log_tx,
        }
    }

    pub async fn resolve_query(
        self: Arc<Self>,
        mut connection: Connection<Arc<UdpSocket>>,
        parsed_packet: anyhow::Result<DnsPacket<'static>>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

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

        let (cache_response, source) = 'resolve: {
            let Ok(query_packet) = parsed_packet.as_ref() else {
                response_packet.header.response_code = ResponseCode::FormatError;
                break 'resolve (false, None);
            };

            if query_packet.header.question_count > 1 || query_packet.questions.len() > 1 {
                response_packet.header.response_code = ResponseCode::FormatError;
                break 'resolve (false, None);
            }
            let question = &query_packet.questions[0];

            let dnssec = if let Some(edns_data) = query_packet
                .edns
                .and_then(|idx| query_packet.additionals.get(idx).and_then(|rr| rr.get_edns_data()))
            {
                edns_data.dnssec_ok_bit
            } else {
                false
            };

            // Check if requested host is in denylist
            if self.denylist_lookup(question, &mut response_packet).await {
                tracing::debug!(
                    qname = ?question.qname,
                    qtype = ?question.query_type,
                    "Found entry in denylist"
                );
                break 'resolve (false, Some(ResponseSource::Denylist));
            }

            // Check if requested host is in allow/hosts list
            if self.allowlist_lookup(question, &mut response_packet).await {
                tracing::debug!(
                    qname = ?question.qname,
                    qtype = ?question.query_type,
                    "Found entry in allowlist"
                );
                break 'resolve (false, Some(ResponseSource::Allowlist));
            }

            // Return if requestor doesn't want recursive resolution
            if !query_packet.header.recursion_desired {
                // TODO: include root/TLD NS in authority section in this case
                break 'resolve (false, Some(ResponseSource::NoRecurse));
            }

            // Check if query is cached
            if self.cache_lookup(question, &mut response_packet, dnssec).await {
                // Cache hit
                break 'resolve (false, Some(ResponseSource::Cache));
            }

            // Try to resolve with the configured upstream resolver
            if let Err(e) = self
                .resolve_with_upstream(question, query_packet.header.id, dnssec, &mut response_packet)
                .await
            {
                tracing::debug!(resolver = ?self.state.upstream_resolver, "Upstream resolution failed: {:#}", e);
            }

            (true, Some(ResponseSource::Upstream))
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
                (!connection.is_tcp()).then(|| requestor_edns_buf_size.unwrap_or(MAX_STANDARD_DNS_MSG_SIZE)),
            )
            .context("error while encoding the response")?;

        if cache_response {
            let mut cache = self.state.cache.write().await;
            cache
                .cache_response(&response_packet)
                .context("bug: caching has failed?")?;
        }

        if let Err(e) = connection.send_encoded_packet(&dst).await {
            // Do not propagate the error, as it's per-user and thus recoverable
            tracing::error!("Error while sending a DNS response: {:#}", e)
        };

        let log_entry = match QueryLog::new_from_response(
            &response_packet,
            connection.get_client_addr().ok(),
            start.elapsed().as_millis() as u32,
            source,
        ) {
            Ok(log_entry) => log_entry,
            Err(e) => {
                tracing::debug!("Failed to create a log entry: {}", e);
                return Ok(());
            }
        };

        // We don't care if the receiving end was dropped already, as we can't do nothing about it
        let _ = self.log_tx.send(log_entry);

        Ok(())
    }

    async fn cache_lookup(&self, question: &Question<'_>, response_packet: &mut DnsPacket<'_>, dnssec: bool) -> bool {
        let cache = self.state.cache.read().await;
        cache.question_lookup(question, response_packet, dnssec)
    }

    async fn denylist_lookup<'a>(&self, question: &Question<'a>, response_packet: &mut DnsPacket<'a>) -> bool {
        let cache = self.state.denylist.read().await;
        let is_in_denylist = cache.contains_entry(&question.qname);
        drop(cache);

        if is_in_denylist {
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
        }

        is_in_denylist
    }

    async fn allowlist_lookup<'a>(&self, question: &Question<'a>, response_packet: &mut DnsPacket<'a>) -> bool {
        let cache = self.state.hosts.read().await;
        let allowlist_records = cache.get_entry(question.qname.as_ref());

        if let Some(records) = allowlist_records {
            response_packet.header.is_authoritative = true;
            records
                .iter()
                .filter(|rdata| match question.query_type {
                    QueryType::ANY => true,
                    qtype => rdata.get_query_type() == qtype,
                })
                .for_each(|rdata| {
                    let rr = ResourceRecord::new(question.qname.clone(), rdata.clone(), Some(180), None);
                    response_packet.answers.push(rr);
                    response_packet.header.answer_rr_count += 1;
                });
        }

        !response_packet.answers.is_empty()
    }

    async fn resolve_with_upstream(
        &self,
        question: &Question<'_>,
        id: u16,
        dnssec: bool,
        response_packet: &mut DnsPacket<'_>,
    ) -> anyhow::Result<()> {
        let upstream_response = match resolve_with_upstream(question, id, self.state.upstream_resolver, dnssec).await {
            Ok((upstream_response, _)) => upstream_response,
            Err(e) => {
                response_packet.header.response_code = ResponseCode::ServerFailure;
                anyhow::bail!("Error while forwarding a request to the upstream resolver: {:#}", e);
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

        Ok(())
    }

    pub async fn add_list_entry(&self, entry: ListEntryKind) -> anyhow::Result<()> {
        match entry {
            ListEntryKind::DenyDomain(domain) => self.state.denylist.write().await.add_entry(domain),
            ListEntryKind::DenyRegex((id, regex)) => self
                .state
                .denylist
                .write()
                .await
                .add_regex(id, regex.context("missing regex when adding a new list entry")?),
            ListEntryKind::Hosts((domain, ip_addr)) => {
                let rdata = match ip_addr {
                    IpAddr::V4(address) => ResourceData::A { address },
                    IpAddr::V6(address) => ResourceData::AAAA { address },
                };
                self.state
                    .hosts
                    .write()
                    .await
                    .add_entry(domain, rdata)
                    .context("error while adding an entry to the hosts file")?
            }
        }

        Ok(())
    }

    pub async fn remove_list_entry(&self, entry: ListEntryKind) {
        match entry {
            ListEntryKind::DenyDomain(domain) => self.state.denylist.write().await.remove_entry(domain),
            ListEntryKind::DenyRegex((id, _)) => self.state.denylist.write().await.remove_regex(id),
            ListEntryKind::Hosts((domain, ip_addr)) => {
                let qtype = match ip_addr {
                    IpAddr::V4(_) => QueryType::A,
                    IpAddr::V6(_) => QueryType::AAAA,
                };
                self.state.hosts.write().await.remove_entry(domain, qtype)
            }
        }
    }
}
