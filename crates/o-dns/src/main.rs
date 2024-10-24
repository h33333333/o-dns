use anyhow::Context as _;
use o_dns::util::{get_dns_query_hash, get_edns_rr, get_empty_dns_packet};
use o_dns::{
    resolve_with_upstream, setup_logging, CacheRecordKind, CachedRecord, State,
    DEFAULT_EDNS_BUF_CAPACITY, MAX_STANDARD_DNS_MSG_SIZE,
};
use o_dns_lib::{ByteBuf, DnsPacket, QueryType, ResourceData, ResourceRecord, ResponseCode};
use o_dns_lib::{EncodeToBuf as _, FromBuf as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

type HandlerResult = anyhow::Result<()>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;

    let state = Arc::new(State::new());
    state
        .hosts
        .write()
        .await
        .add_entry(
            "example.com".to_string(),
            ResourceData::A {
                address: "10.13.37.0".parse().expect("shouldn't fail"),
            },
        )
        .context("failed to add a hosts entry")?;

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
    // Use the smallest EDNS buf size from the requestor's and resolver's buf sizes if EDNS was requested
    let edns_buf_length = parsed_packet.as_ref().ok().and_then(|packet| {
        packet.edns.and_then(|idx| {
            packet
                .additionals
                .get(idx)
                .and_then(ResourceRecord::get_edns_data)
                .map(|data| data.udp_payload_size.min(DEFAULT_EDNS_BUF_CAPACITY))
        })
    });

    // Create an empty response packet
    let mut response_packet = get_empty_dns_packet(
        None,
        parsed_packet.as_ref().ok().map(|packet| &packet.header),
        edns_buf_length,
    );

    let mut hash: Option<u128> = None;
    let mut used_cache = false;
    if let Ok(packet) = parsed_packet.as_ref() {
        if packet.header.question_count == 1 && packet.questions.len() == 1 {
            let question = &packet.questions[0];

            // Calculate hash of the query for caching and cache lookup
            hash = Some(get_dns_query_hash(
                &packet.header,
                question,
                packet.edns.and_then(|idx| packet.additionals.get(idx)),
            ));

            if let Some(cached_response) = state.cache.read().await.get(hash.as_ref().unwrap()) {
                // Response for this query is cached. Check if cache isn't stale
                if (cached_response.added.elapsed().as_secs() as u32) < cached_response.ttd {
                    tracing::debug!(
                        qname = ?question.qname,
                        qtype = ?question.query_type,
                        remaining_time = (cached_response.ttd.saturating_sub(cached_response.added.elapsed().as_secs() as u32)),
                        "Cache hit"
                    );

                    // Cache entry is not stale, use it as a response
                    cached_response.records.iter().for_each(|cached_record| {
                        // Override OPT RR if it's present
                        if cached_record.resource_data.get_query_type() == QueryType::OPT {
                            if response_packet.edns.is_some() {
                                response_packet
                                    .edns
                                    .and_then(|idx| response_packet.additionals.get_mut(idx))
                                    .into_iter()
                                    .for_each(|opt_rr| {
                                        // Override the stub OPT RR that was set when creating an empty response packet
                                        *opt_rr = cached_record.into_rr(&cached_response.added);
                                    });
                            }
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
                    used_cache = true;
                } else {
                    tracing::debug!(
                        qname = ?question.qname,
                        qtype = ?question.query_type,
                        "Found entry in cache, but it's stale. Doing a lookup"
                    );
                }
            } else {
                tracing::debug!(
                    qname = ?question.qname,
                    qtype = ?question.query_type,
                    "Cache miss"
                );
            }

            if !used_cache {
                // Check if requested host is explicitly blacklisted
                if state.blacklist.read().await.contains_entry(&question.qname) {
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
                        let rr =
                            ResourceRecord::new(question.qname.clone(), rdata, Some(180), None);
                        response_packet.answers.push(rr);
                        response_packet.header.answer_rr_count += 1;
                    }
                } else {
                    if let Some(records) = state.hosts.read().await.get_entry(&question.qname) {
                        response_packet.header.is_authoritative = true;
                        records
                            .iter()
                            .filter(|rdata| match question.query_type {
                                QueryType::ANY => true,
                                qtype => rdata.get_query_type() == qtype,
                            })
                            .for_each(|rdata| {
                                let rr = ResourceRecord::new(
                                    question.qname.clone(),
                                    rdata.clone(),
                                    Some(180),
                                    None,
                                );
                                response_packet.answers.push(rr);
                                response_packet.header.answer_rr_count += 1;
                            });
                    } else {
                        // TODO: can cloning be avoided?
                        match resolve_with_upstream(packet.clone(), state.upstream_resolver).await {
                            Ok((mut upstream_response, _)) => {
                                match upstream_response.edns {
                                    Some(idx) => {
                                        // The requestor doesn't support EDNS
                                        if edns_buf_length.is_none() {
                                            // Remove the OPT RR
                                            upstream_response.additionals.remove(idx);
                                            upstream_response.header.additional_rr_count -= 1;
                                        } else {
                                            if let Some(edns_record) =
                                                upstream_response.additionals.get_mut(idx)
                                            {
                                                // Set the EDNS buffer size to the correct one for this resolver
                                                edns_record.class = DEFAULT_EDNS_BUF_CAPACITY as u16
                                            }
                                        }
                                    }
                                    None => {
                                        // Add an OPT RR only if requestor supports EDNS
                                        if let Some(buf_length) = edns_buf_length {
                                            let edns_idx = upstream_response.additionals.len();
                                            let edns_record = get_edns_rr(buf_length as u16, None);
                                            upstream_response.additionals.push(edns_record);
                                            upstream_response.header.additional_rr_count += 1;
                                            upstream_response.edns = Some(edns_idx);
                                        }
                                    }
                                }
                                // Forward the upstream response to the requestor
                                response_packet = upstream_response;
                                // This response is not authoritative
                                response_packet.header.is_authoritative = false;
                            }
                            Err(e) => {
                                response_packet.header.response_code = ResponseCode::ServerFailure;
                                tracing::debug!(resolver = ?state.upstream_resolver, "Error while forwarding a request to the upstream resolver: {}", e);
                            }
                        }
                    }
                }
            }
        } else {
            response_packet.header.response_code = ResponseCode::FormatError;
        }
    } else {
        response_packet.header.response_code = ResponseCode::FormatError;
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
            (!is_using_tcp).then(|| edns_buf_length.unwrap_or(MAX_STANDARD_DNS_MSG_SIZE)),
        )
        .context("error while encoding the response")?;

    // Cache only if response isn't from the cache
    if !used_cache {
        // We can't cache anything if we didn't manage to calculate the hash
        if let Some(hash) = hash {
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

            let mut cache = state.cache.write().await;
            // No point in caching packets with TTL lower than 15s IMO
            if cache_for >= 15 {
                // Set an empty cache record in case there are no records in the response
                cache.set_empty(hash, cache_for);

                response_packet.answers.iter().for_each(|rr| {
                    cache.set(
                        hash,
                        CachedRecord::new(rr.clone(), CacheRecordKind::Answer),
                        cache_for,
                    )
                });
                response_packet.authorities.iter().for_each(|rr| {
                    cache.set(
                        hash,
                        CachedRecord::new(rr.clone(), CacheRecordKind::Authority),
                        cache_for,
                    )
                });
                response_packet.additionals.iter().for_each(|rr| {
                    cache.set(
                        hash,
                        CachedRecord::new(rr.clone(), CacheRecordKind::Additional),
                        cache_for,
                    )
                });
            }
        }
    }

    Ok(dst.into_inner().into_owned())
}
