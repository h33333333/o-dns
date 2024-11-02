use anyhow::Context as _;
use o_dns::util::{
    get_dns_query_hash, get_response_dns_packet, parse_denylist_file, parse_hosts_file,
};
use o_dns::{
    resolve_with_upstream, setup_logging, CacheRecordKind, CachedRecord, State,
    DEFAULT_EDNS_BUF_CAPACITY, MAX_STANDARD_DNS_MSG_SIZE,
};
use o_dns_lib::{ByteBuf, DnsPacket, QueryType, ResourceData, ResourceRecord, ResponseCode};
use o_dns_lib::{EncodeToBuf as _, FromBuf as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

type HandlerResult = anyhow::Result<()>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;

    let state = Arc::new(State::new());

    // Populate the denylist
    parse_denylist_file(
        Path::new("denylist_sample"),
        state.denylist.write().await.deref_mut(),
    )
    .await
    .context("error while parsing the denylist file")?;

    // Populate the hosts file
    parse_hosts_file(
        Path::new("hosts_sample"),
        state.hosts.write().await.deref_mut(),
    )
    .await
    .context("error while parsing the hosts file")?;

    let udp_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:53")
            .await
            .context("error while creating a UDP socket")?,
    );
    let tcp_listener = TcpListener::bind("0.0.0.0:53")
        .await
        .context("error while creating a TcpListener")?;

    let mut recv = vec![0; DEFAULT_EDNS_BUF_CAPACITY];
    let mut handlers: JoinSet<HandlerResult> = JoinSet::new();
    loop {
        tokio::select! {
            result = udp_socket.recv_from(&mut recv) => {
                tracing::trace!("new UDP connection");
                if let Ok((_, from)) = result {
                    let mut reader = ByteBuf::new(&recv);
                    handlers.spawn(
                        handle_udp_connection(udp_socket.clone(), from, DnsPacket::from_buf(&mut reader), state.clone())
                    );
                }
            }
            result = tcp_listener.accept() => {
                tracing::trace!("new TCP connection");
                // TODO: This is bad, as we will have to wait for the client to send the length
                // FIXME: I can easily fix it, as both UdpSocket and TcpListener can be shared between futures
                // using Arc. I can therefore create a pool of workers that will accepts connections in parallel
                if let Ok((mut conn, _)) = result {
                    let mut length = [0; 2];
                    if conn.read_exact(&mut length).await.is_err() {
                        continue;
                    }
                    let to_read = u16::from_be_bytes(length) as usize;
                    if recv.len() < to_read {
                        recv.resize(to_read, 0);
                    }
                    if conn.read_exact(&mut recv[..to_read]).await.is_err() {
                        continue;
                    }
                    let mut reader = ByteBuf::new(&recv);
                    handlers.spawn(
                        handle_tcp_connection(conn, DnsPacket::from_buf(&mut reader), state.clone())
                    );
                }
            }
            Some(result) = handlers.join_next() => {
               result
                   .context("connection handling task failed to execute")?
                   .context("unrecoverable error while handling a query")?;
            }
        };
    }
}

async fn handle_udp_connection(
    socket: Arc<UdpSocket>,
    from: SocketAddr,
    parsed_packet: anyhow::Result<DnsPacket<'static>>,
    state: Arc<State>,
) -> HandlerResult {
    tracing::debug!("handling UDP connection");
    let response = handle_query(parsed_packet, state, false)
        .await
        .context("error while handling the query")?;
    if let Err(e) = socket.send_to(&response, from).await {
        tracing::error!(
            addr = ?from,
            "Error while sending DNS response in UDP handler: {}",
            e
        )
    };
    Ok(())
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    parsed_packet: anyhow::Result<DnsPacket<'static>>,
    state: Arc<State>,
) -> HandlerResult {
    tracing::debug!("handling TCP connection");
    let response = handle_query(parsed_packet, state, true)
        .await
        .context("error while handling the query")?;
    if let Err(e) = stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await
    {
        tracing::error!(
            addr = ?stream.peer_addr(),
            "Error while sending DNS response length in TCP handler: {}",
            e
        )
    } else {
        if let Err(e) = stream.write_all(&response).await {
            tracing::error!(
                addr = ?stream.peer_addr(),
                "Error while sending DNS response in TCP handler: {}",
                e
            )
        }
    }
    Ok(())
}

async fn handle_query(
    parsed_packet: anyhow::Result<DnsPacket<'static>>,
    state: Arc<State>,
    is_using_tcp: bool,
) -> anyhow::Result<Vec<u8>> {
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

    let (hash, from_cache) = 'packet: {
        let Ok(query_packet) = parsed_packet.as_ref() else {
            response_packet.header.response_code = ResponseCode::FormatError;
            break 'packet (None, false);
        };

        if query_packet.header.question_count > 1 || query_packet.questions.len() > 1 {
            response_packet.header.response_code = ResponseCode::FormatError;
            break 'packet (None, false);
        }

        let question = &query_packet.questions[0];

        // Calculate hash of the query for caching and cache lookup
        let hash = Some(get_dns_query_hash(
            &query_packet.header,
            question,
            query_packet
                .edns
                .and_then(|idx| query_packet.additionals.get(idx)),
        ));

        'cache_lookup: {
            let cache = state.cache.read().await;
            let Some(cached_response) = cache.get(hash.as_ref().unwrap()) else {
                tracing::debug!(
                    qname = ?question.qname,
                    qtype = ?question.query_type,
                    "Cache miss"
                );
                break 'cache_lookup;
            };

            // Response for this query is cached. Check if cache isn't stale
            if (cached_response.added.elapsed().as_secs() as u32) >= cached_response.ttd {
                tracing::debug!(
                    qname = ?question.qname,
                    qtype = ?question.query_type,
                    "Found entry in cache, but it's stale. Doing a lookup"
                );
                break 'cache_lookup;
            }

            // Cache entry is not stale, use it as a response
            cached_response.records.iter().for_each(|cached_record| {
                // TODO: don't cache OPT RRs
                if cached_record.resource_data.get_query_type() == QueryType::OPT {
                    // Override OPT RR if it's present
                    response_packet
                        .edns
                        .and_then(|idx| response_packet.additionals.get_mut(idx))
                        .into_iter()
                        .for_each(|opt_rr| {
                            // Override the stub OPT RR that was set when creating an empty response packet
                            *opt_rr = cached_record.into_rr(&cached_response.added);
                        });
                    return;
                }

                let rr = cached_record.into_rr(&cached_response.added);
                match cached_record.kind {
                    CacheRecordKind::Answer => {
                        response_packet.answers.push(rr);
                        response_packet.header.answer_rr_count += 1;
                    }
                    CacheRecordKind::Authority => {
                        response_packet.authorities.push(rr);
                        response_packet.header.authority_rr_count += 1;
                    }
                    CacheRecordKind::Additional => {
                        response_packet.additionals.push(rr);
                        response_packet.header.additional_rr_count += 1;
                    }
                }
            });

            tracing::debug!(
                qname = ?question.qname,
                qtype = ?question.query_type,
                remaining_time = (cached_response.ttd.saturating_sub(cached_response.added.elapsed().as_secs() as u32)),
                "Cache hit"
            );

            break 'packet (hash, true);
        }

        // Check if requested host is explicitly blacklisted
        if state.denylist.read().await.contains_entry(&question.qname) {
            response_packet.header.is_authoritative = true;
            // AD
            response_packet.header.z[1] = true;
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
            break 'packet (hash, false);
        }

        if let Some(records) = state.hosts.read().await.get_entry(question.qname.as_ref()) {
            response_packet.header.is_authoritative = true;
            // AD
            response_packet.header.z[1] = true;
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
            break 'packet (hash, false);
        }

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
                tracing::debug!(resolver = ?state.upstream_resolver, "Error while forwarding a request to the upstream resolver: {}", e);
                break 'packet (hash, false);
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

        (hash, false)
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
            (!is_using_tcp).then(|| requestor_edns_buf_size.unwrap_or(MAX_STANDARD_DNS_MSG_SIZE)),
        )
        .context("error while encoding the response")?;

    // Response caching
    'caching: {
        if from_cache {
            // Cache the response only if it didn't come from the cache already
            break 'caching;
        }

        let Some(hash) = hash else {
            // We can't cache anything if we didn't manage to calculate the hash
            break 'caching;
        };

        let cache_for = match response_packet.header.response_code {
            // Cache for the lowest TTL from all response RRs
            ResponseCode::Success => {
                // Cache for 5 mins by default
                // TODO: fix this, as some responses can be cached for longer
                let mut lowest_ttl = 60 * 5;
                response_packet
                    .answers
                    .iter()
                    .chain(response_packet.authorities.iter())
                    .chain(response_packet.additionals.iter())
                    .for_each(|rr| {
                        if rr.resource_data.get_query_type() != QueryType::OPT {
                            lowest_ttl = lowest_ttl.min(rr.ttl);
                        }
                    });
                lowest_ttl
            }
            // Cache for 1 min
            // TODO: cache NXDOMAIN for SOA TTL (or 1 min if SOA is missing)
            ResponseCode::Refused | ResponseCode::NameError => 60,
            // Cache for 30s
            ResponseCode::ServerFailure => 30,
            // Cache for 5 min
            ResponseCode::NotImplemented => 60 * 5,
            // Don't cache these responses
            ResponseCode::FormatError | ResponseCode::Unknown => 0,
        };

        if cache_for < 15 {
            // No point in caching packets with TTL lower than 15s IMO
            break 'caching;
        }

        let mut cached_rrs = Vec::with_capacity(
            response_packet.answers.len()
                + response_packet.authorities.len()
                + response_packet.additionals.len(),
        );
        response_packet.answers.iter().for_each(|rr| {
            cached_rrs.push(CachedRecord::new(rr.clone(), CacheRecordKind::Answer));
        });
        response_packet.authorities.iter().for_each(|rr| {
            cached_rrs.push(CachedRecord::new(rr.clone(), CacheRecordKind::Authority));
        });
        response_packet.additionals.iter().for_each(|rr| {
            cached_rrs.push(CachedRecord::new(rr.clone(), CacheRecordKind::Additional));
        });

        if !cached_rrs.is_empty() {
            let mut cache = state.cache.write().await;
            cache.set_many(hash, cached_rrs, cache_for, response_packet.header.z[1]);
        }
    };

    Ok(dst.into_inner().into_owned())
}
