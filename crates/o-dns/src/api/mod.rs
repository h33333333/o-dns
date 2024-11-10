mod handlers;
mod routes;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use routes::get_router;
use tokio::net::TcpListener;

use crate::db::SqliteDb;
use crate::State;

pub struct ApiServer {
    router: Router,
}

impl ApiServer {
    pub fn new(db: SqliteDb, resolver_state: State) -> Self {
        let state = ApiState { db, resolver_state };
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
    resolver_state: State,
}
