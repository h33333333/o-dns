use anyhow::Context as _;
use o_dns::util::{parse_denylist_file, parse_hosts_file};
use o_dns::{setup_logging, Connection, Resolver, State, DEFAULT_EDNS_BUF_CAPACITY};
use o_dns_lib::FromBuf as _;
use o_dns_lib::{ByteBuf, DnsPacket};
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
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

    let resolver = Arc::new(Resolver::new(state.clone()));

    let mut recv = ByteBuf::new_from_vec(vec![0; DEFAULT_EDNS_BUF_CAPACITY]);
    let mut handlers: JoinSet<HandlerResult> = JoinSet::new();
    loop {
        let connection: Connection<_> = tokio::select! {
            result = udp_socket.recv_from(&mut recv) => {
                let Ok((_, from)) = result else {
                    continue
                };
                tracing::trace!("new UDP connection");
                Connection::Udp((udp_socket.clone(), Some(from)))
            }
            result = tcp_listener.accept() => {
                // TODO: This is bad, as we will have to wait for the client to send the length
                // FIXME: I can easily fix it, as both UdpSocket and TcpListener can be shared between futures
                // using Arc. I can therefore create a pool of workers that will accepts connections in parallel
                 let Ok((conn, _)) = result else {
                    continue;
                };

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
                .resolve_query(connection, DnsPacket::from_buf(&mut reader)),
        );
    }
}
