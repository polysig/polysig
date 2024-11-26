//! Meeting room and relay service websocket client using
//! the [noise](https://noiseprotocol.org/) protocol for
//! end-to-end encryption intended for multi-party computation
//! and threshold signature applications.
//!
//! To support the web platform this client library uses
//! [web-sys](https://docs.rs/web-sys/latest/web_sys/) when
//! compiling for webassembly otherwise
//! [tokio-tunsgtenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/).

#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod client;
mod error;
mod event_loop;
#[cfg(any(feature = "cggmp", feature = "frost"))]
mod protocols;
mod transport;

pub(crate) use client::{client_impl, client_transport_impl};
pub use event_loop::EventStream;
#[cfg(any(feature = "cggmp", feature = "frost"))]
pub use protocols::*;
pub use transport::{NetworkTransport, Transport};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use native::{
    NativeClient as Client, NativeEventLoop as EventLoop,
};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod web;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web::{WebClient as Client, WebEventLoop as EventLoop};

use polysig_protocol::{
    hex, snow::params::NoiseParams, Chunk, Encoding, Keypair,
    OpaqueMessage, ProtocolState, RequestMessage, SealedEnvelope,
    SessionId, PATTERN,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub(crate) type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;
pub(crate) type Server = Arc<RwLock<Option<ProtocolState>>>;

/// Options used to create a new websocket client.
#[derive(Default)]
pub struct ClientOptions {
    /// Client static keypair.
    pub keypair: Option<Keypair>,
    /// Public key for the server to connect to.
    pub server_public_key: Option<Vec<u8>>,
    /// Noise parameters pattern.
    ///
    /// If no pattern is specified the default noise parameters
    /// pattern is used.
    pub pattern: Option<String>,
}

impl ClientOptions {
    /// Determine if this client expects to use an encrypted channel.
    pub fn is_encrypted(&self) -> bool {
        self.keypair.is_some() && self.server_public_key.is_some()
    }

    /// Build a connection URL for the given server.
    ///
    /// This method appends the public key query string
    /// parameter necessary for connecting to the server.
    pub fn url(&self, server: &str) -> String {
        let server = server.trim_end_matches('/');
        if let Some(keypair) = &self.keypair {
            format!(
                "{}/?public_key={}",
                server,
                hex::encode(keypair.public_key())
            )
        } else {
            server.to_string()
        }
    }

    /// Parse noise parameters from the pattern.
    pub fn params(&self) -> Result<NoiseParams> {
        let pattern = self
            .pattern
            .as_ref()
            .map(|s| &s[..])
            .unwrap_or_else(|| PATTERN);
        Ok(pattern.parse()?)
    }
}

pub use error::Error;

/// Result type for the client library.
pub type Result<T> = std::result::Result<T, Error>;

/// Encrypt a message to send to a peer.
///
/// The protocol must be in transport mode.
async fn encrypt_peer_channel(
    public_key: impl AsRef<[u8]>,
    peer: &mut ProtocolState,
    payload: &[u8],
    encoding: Encoding,
    broadcast: bool,
    session_id: Option<SessionId>,
) -> Result<RequestMessage> {
    match peer {
        ProtocolState::Transport(transport) => {
            let chunks = Chunk::split(payload, transport)?;
            let envelope = SealedEnvelope {
                encoding,
                chunks,
                broadcast,
            };

            let request =
                RequestMessage::Opaque(OpaqueMessage::PeerMessage {
                    public_key: public_key.as_ref().to_vec(),
                    session_id,
                    envelope,
                });

            Ok(request)
        }
        _ => Err(Error::NotTransportState),
    }
}

/// Decrypt a message received from a peer.
///
/// The protocol must be in transport mode.
async fn decrypt_peer_channel(
    peer: &mut ProtocolState,
    envelope: SealedEnvelope,
) -> Result<(Encoding, Vec<u8>)> {
    match peer {
        ProtocolState::Transport(transport) => {
            let contents = Chunk::join(envelope.chunks, transport)?;
            Ok((envelope.encoding, contents))
        }
        _ => Err(Error::NotTransportState),
    }
}
