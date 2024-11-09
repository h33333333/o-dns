use std::net::SocketAddr;

use anyhow::Context as _;
use o_dns_lib::{ByteBuf, DnsPacket, EncodeToBuf as _, FromBuf as _, Question};
use tokio::net::{TcpStream, UdpSocket};

use crate::connection::Connection;
use crate::util::get_query_dns_packet;
use crate::{DEFAULT_EDNS_BUF_CAPACITY, MAX_STANDARD_DNS_MSG_SIZE};

pub(super) async fn resolve_with_upstream(
    question: &Question<'_>,
    id: u16,
    upstream_resolver: SocketAddr,
    enable_dnssec: bool,
) -> anyhow::Result<(DnsPacket<'static>, usize)> {
    let mut buf = ByteBuf::new_empty(Some(DEFAULT_EDNS_BUF_CAPACITY));

    let mut packet = get_query_dns_packet(Some(id), enable_dnssec);
    packet.questions.push(question.clone());
    packet.header.question_count += 1;

    let mut force_tcp = false;
    loop {
        packet
            // No need to verify the packet's size here, as we can just fall back to TCP if it's too big
            .encode_to_buf(&mut buf, None)
            .context("error while encoding the DNS packet")?;

        // TODO: verify whether the upstream server supports EDNS by maintaining a cache.
        //   if it's the first query to this server -> assume no EDNS by default but add OPT RR
        let mut connection: Connection<_> = if force_tcp || buf.len() > MAX_STANDARD_DNS_MSG_SIZE {
            Connection::Tcp(
                TcpStream::connect(upstream_resolver)
                    .await
                    .context("TCP: error while connecting to the upstream resolver")?,
            )
        } else {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .context("UDP: unable to bind a socket")?;
            socket
                .connect(upstream_resolver)
                .await
                .context("UDP: error while connecting to the upstream resolver")?;
            Connection::Udp((socket, None))
        };

        connection
            .send_encoded_packet(&buf)
            .await
            .context("error while forwarding the question")?;

        let response_length = connection
            .read(&mut buf)
            .await
            .context("error while reading the response")?;

        let response = DnsPacket::from_buf(&mut buf).context("error while decoding the response")?;

        if response.header.truncation {
            if connection.is_tcp() {
                anyhow::bail!("response truncation when using TCP");
            }
            // Retry using TCP
            force_tcp = true;
            buf.reset_pos();
            // Clear the buf because it's reused for both sending and receiving
            buf.clear();

            continue;
        }

        break Ok((response, response_length));
    }
}
