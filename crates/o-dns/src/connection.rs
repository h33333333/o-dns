use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context as _;
use o_dns_lib::ByteBuf;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

use crate::DEFAULT_EDNS_BUF_CAPACITY;

/// An enum that abstracts the underlying connection to simplify the logic inside the resolver
pub enum Connection<U: AsyncUdpSocket> {
    Tcp(TcpStream),
    Udp((U, Option<SocketAddr>)),
}

pub trait AsyncUdpSocket {
    fn send(&self, buf: &[u8]) -> impl std::future::Future<Output = std::io::Result<usize>>;
    fn send_to<A: ToSocketAddrs>(
        &self,
        buf: &[u8],
        target: A,
    ) -> impl std::future::Future<Output = std::io::Result<usize>>;
    fn recv(&self, buf: &mut [u8]) -> impl std::future::Future<Output = std::io::Result<usize>>;
    fn peer_addr(&self) -> anyhow::Result<IpAddr>;
}

impl AsyncUdpSocket for UdpSocket {
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf).await
    }

    async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> std::io::Result<usize> {
        self.send_to(buf, target).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf).await
    }

    fn peer_addr(&self) -> anyhow::Result<IpAddr> {
        self.peer_addr()
            .map(|socket_addr| socket_addr.ip())
            .context("error while getting peer's addr")
    }
}

impl AsyncUdpSocket for Arc<UdpSocket> {
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.as_ref().send(buf).await
    }

    async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> std::io::Result<usize> {
        self.as_ref().send_to(buf, target).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.as_ref().recv(buf).await
    }

    fn peer_addr(&self) -> anyhow::Result<IpAddr> {
        self.as_ref()
            .peer_addr()
            .map(|socket_addr| socket_addr.ip())
            .context("error while getting peer's addr")
    }
}

impl<U: AsyncUdpSocket> Connection<U> {
    pub async fn send_encoded_packet(&mut self, src: &[u8]) -> anyhow::Result<()> {
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
                    .context("TCP: error while sending a DNS packet")?;
            }
            Connection::Udp((socket, addr)) => {
                if let Some(addr) = addr {
                    socket
                        .send_to(src, &*addr)
                        .await
                        .with_context(|| format!("UDP: error while sending a DNS packet to {}", addr))?;
                } else {
                    socket
                        .send(src)
                        .await
                        .context("UDP: error while sending a DNS packet")?;
                }
            }
        };

        Ok(())
    }

    pub async fn read(&mut self, dst: &mut ByteBuf<'_>) -> anyhow::Result<usize> {
        let packet_length = match self {
            Connection::Tcp(socket) => {
                let length = socket
                    .read_u16()
                    .await
                    .context("TCP: error while reading packet's length")? as usize;
                if dst.len() < length {
                    dst.resize(length);
                }
                socket
                    .read_exact(&mut dst[..length])
                    .await
                    .context("TCP: error while reading a packet")?;
                length
            }
            Connection::Udp((socket, _)) => {
                if dst.len() < DEFAULT_EDNS_BUF_CAPACITY {
                    dst.resize(DEFAULT_EDNS_BUF_CAPACITY);
                }
                socket.recv(dst).await.context("UDP: error while reading a packet")?
            }
        };

        Ok(packet_length)
    }

    pub fn get_client_addr(&self) -> anyhow::Result<IpAddr> {
        match self {
            Connection::Tcp(socket) => socket
                .peer_addr()
                .map(|socket_addr| socket_addr.ip())
                .context("bug: TCP socket is not connected?"),
            Connection::Udp((socket, addr)) => addr
                .map(|socket_addr| socket_addr.ip())
                .or_else(|| socket.peer_addr().ok())
                .context("bug: UDP socket is not connected and explicit addr is missing?"),
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Connection::Tcp(_))
    }
}
