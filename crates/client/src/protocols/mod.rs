use crate::{Client, ClientOptions, EventLoop, Result, Transport};
use async_trait::async_trait;
use polysig_protocol::{hex, Event, Keypair, Parameters};
use serde::{Deserialize, Serialize};

mod bridge;
pub mod meeting;
mod session;

#[cfg(feature = "cggmp")]
pub mod cggmp;

#[cfg(feature = "frost")]
pub mod frost;

pub(crate) use bridge::Bridge;
pub use bridge::{
    wait_for_close, wait_for_driver, wait_for_session_finish,
};

pub use session::{
    wait_for_session, SessionEventHandler, SessionHandler,
    SessionInitiator, SessionParticipant,
};

/// Server options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOptions {
    /// URL for the server.
    pub server_url: String,
    /// Server public key.
    pub server_public_key: Vec<u8>,
    /// Noise parameters pattern.
    pub pattern: Option<String>,
}

/// Options used to drive a session to completion.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOptions {
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}

/// Drives a protocol to completion bridging between
/// the network transport and local computation.
#[async_trait]
pub trait Driver {
    /// Output yielded when the driver completes.
    type Output;

    /// Handle an incoming event.
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>>;

    /// Start running the protocol.
    async fn execute(&mut self) -> Result<()>;

    /// Consume this driver into the underlying transport.
    fn into_transport(self) -> Transport;
}

/// Create a new client using the provided session options.
pub(crate) async fn new_client(
    options: SessionOptions,
) -> Result<(Client, EventLoop)> {
    let server_url = options.server.server_url;
    let options = ClientOptions {
        keypair: Some(options.keypair),
        server_public_key: Some(options.server.server_public_key),
        pattern: options.server.pattern,
    };
    let url = options.url(&server_url);
    Ok(Client::new(&url, options).await?)
}

pub(crate) fn public_key_to_str(public_key: &[u8]) -> String {
    hex::encode(&public_key[0..6])
}
