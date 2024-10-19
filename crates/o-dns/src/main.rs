use anyhow::Context;
use o_dns::util::get_empty_dns_packet;
use o_dns::{setup_logging, State, DEFAULT_BUF_CAPACITY};
use o_dns_lib::{ByteBuf, DnsPacket, ResourceData, ResourceRecord, ResponseCode};
use o_dns_lib::{EncodeToBuf, FromBuf};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    let mut recv = vec![0; DEFAULT_BUF_CAPACITY];
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
    let response = handle_query(parsed_packet, state)
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
    let response = handle_query(parsed_packet, state)
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
) -> anyhow::Result<Vec<u8>> {
    let include_edns = parsed_packet
        .as_ref()
        .is_ok_and(|packet| packet.edns.is_some());
    // Create an empty response packet
    let mut response_packet = get_empty_dns_packet(
        None,
        parsed_packet.as_ref().ok().map(|packet| &packet.header),
        include_edns,
    );

    if let Ok(packet) = parsed_packet.as_ref() {
        if packet.header.question_count == 1 && packet.questions.len() == 1 {
            let question = &packet.questions[0];
            // Check if requested host is explicitly blacklisted
            if state.blacklist.read().await.contains_entry(&question.qname) {
                // TODO: Add a 0.0.0.0 response if blacklisted
            }
            if let Some(records) = state.hosts.read().await.get_entry(&question.qname) {
                response_packet.header.is_authoritative = true;
                records
                    .iter()
                    .filter(|record| record.get_query_type() == question.query_type)
                    .for_each(|record| {
                        let rr =
                            ResourceRecord::new(&question.qname, record.clone(), Some(180), None);
                        response_packet.answers.push(rr);
                        response_packet.header.answer_rr_count += 1;
                    });
            } else {
                // TODO: forward request to the configured upstream resolver
            }
        } else {
            response_packet.header.response_code = ResponseCode::FormatError;
        }
    } else {
        response_packet.header.response_code = ResponseCode::FormatError;
    };

    // Encode the response packet
    let mut dst = ByteBuf::new_empty(Some(DEFAULT_BUF_CAPACITY));
    response_packet
        .encode_to_buf(&mut dst)
        .context("error while encoding the response")?;

    Ok(dst.into_inner().into_owned())
}
