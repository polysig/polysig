pub(crate) mod meeting_point;
pub(crate) mod peer_channel;
#[cfg(any(feature = "cggmp", feature = "frost-ed25519"))]
pub(crate) mod session_handshake;
pub(crate) mod session_timeout;
pub(crate) mod socket_close;

pub(crate) mod meeting_server;
pub use meeting_server::spawn_meeting_server;

pub(crate) mod relay_server;
pub use relay_server::{server_public_key, spawn_server};

use polysig_client::{Client, ClientOptions, EventLoop};
use polysig_protocol::Keypair;

#[allow(dead_code)]
pub fn init_tracing() {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .try_init();
}

/// Create a new client connected to the mock server.
pub async fn new_client<E: From<polysig_client::Error>>(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<(Client, EventLoop, Keypair), E> {
    let keypair = Keypair::generate().map_err(|e| {
        let err = polysig_client::Error::from(e);
        err
    })?;
    let copy = keypair.clone();
    let (client, event_loop) =
        new_client_with_keypair(server, server_public_key, keypair)
            .await?;
    Ok((client, event_loop, copy))
}

pub async fn new_client_with_keypair<
    E: From<polysig_client::Error>,
>(
    server: &str,
    server_public_key: Vec<u8>,
    keypair: Keypair,
) -> Result<(Client, EventLoop), E> {
    let options = ClientOptions {
        keypair: Some(keypair),
        server_public_key: Some(server_public_key),
        pattern: None,
    };
    let url = options.url(server);
    let (client, event_loop) = Client::new(&url, options).await?;
    Ok((client, event_loop))
}
