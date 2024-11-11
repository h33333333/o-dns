mod handlers;
mod routes;
mod util;

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
use routes::get_router;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::db::SqliteDb;
use crate::server::DnsServerCommand;

pub struct ApiServer {
    router: Router,
}

impl ApiServer {
    pub fn new(db: SqliteDb, dns_server_command_tx: Sender<DnsServerCommand>) -> Self {
        let state = ApiState {
            db,
            command_tx: dns_server_command_tx,
        };
        let router = get_router(state);

        ApiServer { router }
    }

    pub async fn serve(self, listen_on: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen_on)
            .await
            .context("failed to bind a listener")?;

        axum::serve(listener, self.router)
            .await
            .context("error while serving requests")
    }
}

struct ApiState {
    db: SqliteDb,
    command_tx: Sender<DnsServerCommand>,
}
