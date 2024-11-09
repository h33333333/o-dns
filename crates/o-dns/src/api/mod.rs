mod handlers;
mod routes;
mod util;

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
use routes::get_router;
use sqlx::SqlitePool;
use tokio::net::TcpListener;

pub struct ApiServer {
    router: Router,
}
impl ApiServer {
    pub fn new(connection_pool: SqlitePool) -> Self {
        let state = ApiState { connection_pool };
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

#[derive(Clone)]
struct ApiState {
    connection_pool: SqlitePool,
}
