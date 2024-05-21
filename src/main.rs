use daily_tookay::server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = Server::new();
    server.start().await?;
    Ok(())
}
