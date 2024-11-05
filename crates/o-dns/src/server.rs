use crate::{Connection, Resolver, State, DEFAULT_EDNS_BUF_CAPACITY};
use anyhow::Context as _;
use o_dns_lib::FromBuf as _;
use o_dns_lib::{ByteBuf, DnsPacket};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tracing::Instrument;

type HandlerResult = anyhow::Result<()>;

pub struct DnsServer {
    udp_socket: Arc<UdpSocket>,
    tcp_listener: Arc<TcpListener>,
    resolver: Arc<Resolver>,
    workers: JoinSet<HandlerResult>,
}

impl DnsServer {
    pub async fn new() -> anyhow::Result<Self> {
        let udp_socket = Arc::new(
            UdpSocket::bind("0.0.0.0:53")
                .await
                .context("error while creating a UDP socket")?,
        );
        let tcp_listener = Arc::new(
            TcpListener::bind("0.0.0.0:53")
                .await
                .context("error while creating a TcpListener")?,
        );

        let state = State::new(
            Some(Path::new("denylist_sample")),
            Some(Path::new("hosts_sample")),
        )
        .await
        .context("failed to instantiate a shared state")?;

        let resolver = Arc::new(Resolver::new(state));

        Ok(DnsServer {
            udp_socket,
            tcp_listener,
            resolver,
            workers: JoinSet::new(),
        })
    }

    pub async fn add_workers(&mut self, n: usize) {
        for idx in 0..n {
            let udp_socket = self.udp_socket.clone();
            let tcp_listener = self.tcp_listener.clone();
            let resolver = self.resolver.clone();

            self.workers.spawn(
                handle_incoming_requests(udp_socket, tcp_listener, resolver)
                    .instrument(tracing::trace_span!("", worker = idx)),
            );
        }
    }

    pub async fn block_until_completion(&mut self) -> anyhow::Result<()> {
        loop {
            if let Some(result) = self.workers.join_next().await {
                if let Err(e) = result.context("worker task failed to execute")? {
                    tracing::debug!("Error in a worker: {}", e);
                }
            } else {
                // No workers left
                break;
            }
        }

        Ok(())
    }
}

async fn handle_incoming_requests(
    udp_socket: Arc<UdpSocket>,
    tcp_listener: Arc<TcpListener>,
    resolver: Arc<Resolver>,
) -> HandlerResult {
    let mut recv = ByteBuf::new_from_vec(vec![0; DEFAULT_EDNS_BUF_CAPACITY]);
    let mut handlers: JoinSet<HandlerResult> = JoinSet::new();
    loop {
        let connection: Connection<_> = tokio::select! {
            Ok((_, from)) = udp_socket.recv_from(&mut recv) => {
                tracing::trace!("new UDP connection");

                Connection::Udp((udp_socket.clone(), Some(from)))
            }
            Ok((conn, _)) = tcp_listener.accept() => {
                 tracing::trace!("new TCP connection");

                 let mut connection = Connection::Tcp(conn);
                 if connection.read(&mut recv).await.is_err() {
                     continue;
                 };

                connection
            }
            Some(result) = handlers.join_next() => {
               result
                   .context("connection handling task failed to execute")?
                   .context("unrecoverable error while handling a query")?;
               continue;
            }
        };

        let mut reader = ByteBuf::new(&recv);
        handlers.spawn(
            resolver
                .clone()
                .resolve_query(connection, DnsPacket::from_buf(&mut reader))
                .in_current_span(),
        );
    }
}
