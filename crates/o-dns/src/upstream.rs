use crate::{util::get_query_dns_packet, DEFAULT_EDNS_BUF_CAPACITY, MAX_STANDARD_DNS_MSG_SIZE};
use anyhow::Context as _;
use o_dns_lib::{ByteBuf, DnsPacket, EncodeToBuf as _, FromBuf as _, Question};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, UdpSocket},
};

pub async fn resolve_with_upstream(
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
        // Clear the buf in case it's a retry over TCP
        buf.clear();
        packet
            // No need to verify the packet's size here, as it was done above
            .encode_to_buf(&mut buf, None)
            .context("error while encoding the DNS packet")?;

        // TODO: verify whether the upstream server supports EDNS by maintaining a cache.
        //   if it's the first query to this server -> assume no EDNS by default but add OPT RR
        let mut connection: Connection = if force_tcp || buf.len() > MAX_STANDARD_DNS_MSG_SIZE {
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
            Connection::Udp(socket)
        };

        connection
            .send_encoded_packet(&buf)
            .await
            .context("error while forwarding the question")?;

        let response_length = connection
            .read(&mut buf)
            .await
            .context("error while reading the response")?;

        let response =
            DnsPacket::from_buf(&mut buf).context("error while decoding the response")?;

        if response.header.truncation {
            if connection.is_tcp() {
                anyhow::bail!("response truncation when using TCP");
            }
            // Retry using TCP
            force_tcp = true;
            buf.reset_pos();
            continue;
        }

        break Ok((response, response_length));
    }
}

/// An enum that abstracts the underlying connection to simplify the logic inside the resolver
enum Connection {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Connection {
    async fn send_encoded_packet(&mut self, src: &[u8]) -> anyhow::Result<()> {
        match self {
            Connection::Tcp(socket) => {
                let length = (src.len() as u16).to_be_bytes();
                socket
                    .write_all(&length)
                    .await
                    .context("TCP: error while sending packet's length")?;
                socket
                    .write_all(src)
                    .await
                    .context("TCP: error while forwarding a DNS question")?;
            }
            Connection::Udp(socket) => {
                socket
                    .send(src)
                    .await
                    .context("UDP: error while forwarding a DNS question")?;
            }
        };

        Ok(())
    }

    async fn read(&mut self, dst: &mut ByteBuf<'_>) -> anyhow::Result<usize> {
        let packet_length = match self {
            Connection::Tcp(socket) => {
                let length = socket
                    .read_u16()
                    .await
                    .context("TCP: error while reading packet's length")?
                    as usize;
                if dst.len() < length {
                    dst.resize(length);
                }
                socket
                    .read_exact(dst)
                    .await
                    .context("TCP: error while reading a packet")?;
                length
            }
            Connection::Udp(socket) => {
                if dst.len() < DEFAULT_EDNS_BUF_CAPACITY {
                    dst.resize(DEFAULT_EDNS_BUF_CAPACITY);
                }
                socket
                    .recv(dst)
                    .await
                    .context("UDP: error while reading a packet")?
            }
        };

        Ok(packet_length)
    }

    fn is_tcp(&self) -> bool {
        match self {
            Connection::Tcp(_) => true,
            _ => false,
        }
    }
}
