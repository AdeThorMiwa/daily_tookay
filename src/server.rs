use axum::{routing::post, Router};

use crate::routes;

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let app = Router::new().route(
            "/authenticate",
            post(routes::authenticate::authenticate_user),
        );

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
