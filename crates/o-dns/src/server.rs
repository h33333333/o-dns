use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use o_dns_lib::{ByteBuf, DnsPacket, FromBuf as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{Receiver, UnboundedSender};
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::db::QueryLog;
use crate::hosts::ListEntryKind;
use crate::{Connection, Resolver, State, DEFAULT_EDNS_BUF_CAPACITY};

type HandlerResult = anyhow::Result<()>;

#[derive(Debug)]
pub enum DnsServerCommand {
    AddNewListEntry(ListEntryKind),
}

pub struct DnsServer {
    udp_socket: Arc<UdpSocket>,
    tcp_listener: Arc<TcpListener>,
    resolver: Arc<Resolver>,
    workers: JoinSet<HandlerResult>,
    command_rx: Receiver<DnsServerCommand>,
}

impl DnsServer {
    pub async fn new(
        listen_on: SocketAddr,
        resolver_addr: SocketAddr,
        log_tx: UnboundedSender<QueryLog>,
        command_rx: Receiver<DnsServerCommand>,
    ) -> anyhow::Result<Self> {
        let udp_socket = Arc::new(
            UdpSocket::bind(listen_on)
                .await
                .context("error while creating a UDP socket")?,
        );

        let tcp_listener = Arc::new(
            TcpListener::bind(listen_on)
                .await
                .context("error while creating a TcpListener")?,
        );

        let state = State::new(resolver_addr)
            .await
            .context("failed to instantiate a shared state")?;

        let resolver = Arc::new(Resolver::new(state, log_tx));

        Ok(DnsServer {
            udp_socket,
            tcp_listener,
            resolver,
            workers: JoinSet::new(),
            command_rx,
        })
    }

    pub async fn new_with_workers(
        listen_on: SocketAddr,
        resolver_addr: SocketAddr,
        log_tx: UnboundedSender<QueryLog>,
        max_parallel_connections: u8,
        command_rx: Receiver<DnsServerCommand>,
    ) -> anyhow::Result<Self> {
        let mut server = DnsServer::new(listen_on, resolver_addr, log_tx, command_rx).await?;
        server.add_workers(max_parallel_connections).await;

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
        loop {
            tokio::select! {
                Some(result) = self.workers.join_next() => {
                    if let Err(e) = result.context("worker task failed to execute")? {
                        tracing::debug!("Error in a worker: {}", e);
                    }
                    if self.workers.is_empty() {
                        break;
                    }
                    continue;
                }
                Some(cmd) = self.command_rx.recv() => {
                    tracing::debug!(cmd = ?cmd, "DNS server received a new command");
                    if let Err(e) = self.process_command(cmd).await {
                        tracing::debug!("Error while processing a DNS server command: {:#}", e);
                    }
                }
            };
        }

        Ok(())
    }

    pub async fn process_command(&self, command: DnsServerCommand) -> anyhow::Result<()> {
        match command {
            DnsServerCommand::AddNewListEntry(list_entry) => self
                .resolver
                .add_list_entry(list_entry)
                .await
                .context("failed to add a new list entry")?,
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
