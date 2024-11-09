use crate::db::get_sqlite_connection_pool;
use crate::query_log::QueryLogger;
use crate::{Args, Connection, Resolver, State, DEFAULT_EDNS_BUF_CAPACITY};
use anyhow::Context as _;
use o_dns_lib::FromBuf as _;
use o_dns_lib::{ByteBuf, DnsPacket};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::{JoinSet, LocalSet};
use tracing::Instrument;

type HandlerResult = anyhow::Result<()>;

pub struct DnsServer {
    udp_socket: Arc<UdpSocket>,
    tcp_listener: Arc<TcpListener>,
    resolver: Arc<Resolver>,
    workers: JoinSet<HandlerResult>,
    query_logger: QueryLogger,
}

impl DnsServer {
    pub async fn new(args: &Args) -> anyhow::Result<Self> {
        let bind_addr = SocketAddr::new(args.host, args.port);

        let udp_socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .await
                .context("error while creating a UDP socket")?,
        );

        let tcp_listener = Arc::new(
            TcpListener::bind(bind_addr)
                .await
                .context("error while creating a TcpListener")?,
        );

        let resolver_addr = SocketAddr::new(args.upstream_resolver, args.upstream_port);
        let state = State::new(
            args.denylist_path.as_deref(),
            args.allowlist_path.as_deref(),
            resolver_addr,
        )
        .await
        .context("failed to instantiate a shared state")?;

        let connection_pool = get_sqlite_connection_pool(&args.query_log_path)
            .await
            .context("failed to create an SQLite connection pool")?;

        // Channel for query logs
        let (log_tx, log_rx) = unbounded_channel();

        let resolver = Arc::new(Resolver::new(state, log_tx));
        let query_logger = QueryLogger::new(log_rx, connection_pool.clone())
            .await
            .context("error while creating a query logger")?;

        Ok(DnsServer {
            udp_socket,
            tcp_listener,
            resolver,
            workers: JoinSet::new(),
            query_logger,
        })
    }

    pub async fn new_with_workers(args: &Args) -> anyhow::Result<Self> {
        let mut server = DnsServer::new(args).await?;
        server.add_workers(args.max_parallel_connections).await;

        Ok(server)
    }

    pub async fn add_workers(&mut self, n: u8) {
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

    pub async fn block_until_completion(mut self) -> anyhow::Result<()> {
        let mut set = LocalSet::new();
        set.spawn_local(async move {
            if let Err(e) = self.query_logger.watch_for_logs().await {
                tracing::debug!("Error in query logger: {}", e);
            }
        });

        loop {
            tokio::select! {
                result = self.workers.join_next() => {
                    if let Some(result) = result {
                        if let Err(e) = result.context("worker task failed to execute")? {
                            tracing::debug!("Error in a worker: {}", e);
                        }
                    } else {
                        // No workers left
                        break;
                    }
                }
                _ = &mut set => {
                    tracing::trace!("Query logger was shut down");
                }
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
