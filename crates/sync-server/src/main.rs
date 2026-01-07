//! Self-host: run this binary in Docker with `DATABASE_URL` (PostgreSQL) and
//! `JWT_SECRET` set; override `BIND_ADDR` if needed. Serve behind TLS.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cfg = rina_sync_server::Config::from_env()?;
    let pool = rina_sync_server::init_db(&cfg.database_url).await?;
    let addr: SocketAddr = cfg.bind_addr.parse()?;
    let state = rina_sync_server::AppState { pool, cfg: std::sync::Arc::new(cfg.clone()) };
    let app = rina_sync_server::router(state);
    tracing::info!(%addr, "sync server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
