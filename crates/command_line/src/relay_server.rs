//! Command line tool for the polysig websocket relay service that
//! uses the [noise](https://noiseprotocol.org/) protocol for end-to-end
//! encryption intended for multi-party computation and threshold
//! signature applications.
//!
//! See [polysig_relay_server::ServerConfig] for configuration details.
//!
//! # Installation
//!
//! ```no_run
//! cargo install polysig-server
//! ```
//! # Generate keypair
//!
//! First generate a keypair for the server:
//!
//! ```no_run
//! polysig-keygen keypair server.pem
//! ```
//!
//! # Configuration
//!
//! Then create a configuration file for the server (`config.toml`):
//!
//! ```no_run
//! key = "server.pem"
//! ```
//!
//! # Server
//!
//! Start the relay websocket service:
//!
//! ```no_run
//! polysig-relay config.toml
//! ```
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::Result;
use axum_server::Handle;
use clap::Parser;
use polysig_relay_server::{RelayServer, ServerConfig};
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};

/// Relay websocket server.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RelayService {
    /// Override the interval to poll for expired sessions in seconds.
    #[clap(long)]
    session_interval: Option<u64>,

    /// Override the default session timeout in seconds.
    #[clap(long)]
    session_timeout: Option<u64>,

    /// Bind to host:port.
    #[clap(short, long, default_value = "0.0.0.0:7007")]
    bind: String,

    /// Config file to load.
    config: PathBuf,
}

/// Start the web server.
async fn start_server(
    bind: String,
    config: PathBuf,
    interval: Option<u64>,
    session_timeout: Option<u64>,
) -> Result<()> {
    let (mut config, keypair) = ServerConfig::load(&config).await?;

    if let Some(interval) = interval {
        config.session.interval = interval;
    }

    if let Some(session_timeout) = session_timeout {
        config.session.timeout = session_timeout;
    }

    let handle = Handle::new();
    let addr = SocketAddr::from_str(&bind)?;
    let server = RelayServer::new(config, keypair);
    server.start(addr, handle).await?;
    Ok(())
}

/// Parse arguments and run the program.
async fn run() -> Result<()> {
    let args = RelayService::parse();
    start_server(
        args.bind,
        args.config,
        args.session_interval,
        args.session_timeout,
    )
    .await?;
    Ok(())
}

#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "polysig_relay_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}
