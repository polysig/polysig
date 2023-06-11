use http::StatusCode;
use snow::{HandshakeState, TransportState};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

use crate::encoding::types;

/// Identifier for sessions.
pub type SessionId = uuid::Uuid;

/// Enumeration of protocol states.
pub enum ProtocolState {
    /// Noise handshake state.
    Handshake(Box<HandshakeState>),
    /// Noise transport state.
    Transport(TransportState),
}

/// Handshake messages.
#[derive(Default, Debug)]
pub enum HandshakeMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Handshake initiator.
    Initiator(usize, Vec<u8>),
    /// Handshake responder.
    Responder(usize, Vec<u8>),
}

impl From<&HandshakeMessage> for u8 {
    fn from(value: &HandshakeMessage) -> Self {
        match value {
            HandshakeMessage::Noop => types::NOOP,
            HandshakeMessage::Initiator(_, _) => {
                types::HANDSHAKE_INITIATOR
            }
            HandshakeMessage::Responder(_, _) => {
                types::HANDSHAKE_RESPONDER
            }
        }
    }
}

/// Transparent messaages are not encrypted.
#[derive(Default, Debug)]
pub enum TransparentMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Handshake message.
    ServerHandshake(HandshakeMessage),
    /// Relayed peer handshake message.
    PeerHandshake {
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Handshake message.
        message: HandshakeMessage,
    },
}

impl From<&TransparentMessage> for u8 {
    fn from(value: &TransparentMessage) -> Self {
        match value {
            TransparentMessage::Noop => types::NOOP,
            TransparentMessage::ServerHandshake(_) => {
                types::HANDSHAKE_SERVER
            }
            TransparentMessage::PeerHandshake { .. } => {
                types::HANDSHAKE_PEER
            }
        }
    }
}

/// Message sent between the server and a client.
#[derive(Default, Debug)]
pub enum ServerMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),
    /// Request a new session.
    NewSession(SessionRequest),
    /// Request to notify all participants when the
    /// session is ready.
    SessionReadyNotify(SessionId),
    /// Register a peer connection in a session.
    SessionConnection {
        /// Session identifier.
        session_id: SessionId,
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Request to notify all participants when the
    /// session is active.
    SessionActiveNotify(SessionId),
    /// Response to a new session request.
    SessionCreated(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all completed
    /// the server handshake.
    SessionReady(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all established
    /// peer connections to each other.
    SessionActive(SessionState),
}

impl From<&ServerMessage> for u8 {
    fn from(value: &ServerMessage) -> Self {
        match value {
            ServerMessage::Noop => types::NOOP,
            ServerMessage::Error(_, _) => types::ERROR,
            ServerMessage::NewSession(_) => types::SESSION_NEW,
            ServerMessage::SessionReadyNotify(_) => {
                types::SESSION_READY_NOTIFY
            }
            ServerMessage::SessionConnection { .. } => {
                types::SESSION_CONNECTION
            }
            ServerMessage::SessionActiveNotify(_) => {
                types::SESSION_ACTIVE_NOTIFY
            }
            ServerMessage::SessionCreated(_) => {
                types::SESSION_CREATED
            }
            ServerMessage::SessionReady(_) => types::SESSION_READY,
            ServerMessage::SessionActive(_) => types::SESSION_ACTIVE,
        }
    }
}

/// Opaque messaages are encrypted.
#[derive(Default, Debug)]
pub enum OpaqueMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Encrypted message sent between the server and a client.
    ///
    /// After decrypting it can be decoded to a server message.
    ServerMessage(SealedEnvelope),

    /// Relay an encrypted message to a peer.
    PeerMessage {
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Session identifier.
        session_id: Option<SessionId>,
        /// Message envelope.
        envelope: SealedEnvelope,
    },
}

impl From<&OpaqueMessage> for u8 {
    fn from(value: &OpaqueMessage) -> Self {
        match value {
            OpaqueMessage::Noop => types::NOOP,
            OpaqueMessage::ServerMessage(_) => types::OPAQUE_SERVER,
            OpaqueMessage::PeerMessage { .. } => types::OPAQUE_PEER,
        }
    }
}

/// Request message sent to the server or another peer.
#[derive(Default, Debug)]
pub enum RequestMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

    /// Opaque encrypted messages.
    Opaque(OpaqueMessage),
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::Noop => types::NOOP,
            RequestMessage::Transparent(_) => types::TRANSPARENT,
            RequestMessage::Opaque(_) => types::OPAQUE,
        }
    }
}

/// Response message sent by the server or a peer.
#[derive(Default, Debug)]
pub enum ResponseMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

    /// Opaque encrypted messages.
    Opaque(OpaqueMessage),
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::Noop => types::NOOP,
            ResponseMessage::Transparent(_) => types::TRANSPARENT,
            ResponseMessage::Opaque(_) => types::OPAQUE,
        }
    }
}

/// Encoding for message payloads.
#[derive(Default, Clone, Copy, Debug)]
pub enum Encoding {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Binary encoding.
    Blob,
    /// JSON encoding.
    Json,
}

impl From<Encoding> for u8 {
    fn from(value: Encoding) -> Self {
        match value {
            Encoding::Noop => types::NOOP,
            Encoding::Blob => types::ENCODING_BLOB,
            Encoding::Json => types::ENCODING_JSON,
        }
    }
}

/// Sealed envelope is an encrypted message.
///
/// The payload has been encrypted using the noise protocol
/// channel and the recipient must decrypt and decode the payload.
#[derive(Default, Debug)]
pub struct SealedEnvelope {
    /// Encoding for the payload.
    pub encoding: Encoding,
    /// Length of the payload data.
    pub length: usize,
    /// Encrypted payload.
    pub payload: Vec<u8>,
    /// Whether this is a broadcast message.
    pub broadcast: bool,
}

/// Session is a namespace for a group of participants
/// to communicate for a series of rounds.
///
/// Use this for the keygen, signing or key refresh
/// of an MPC protocol.
pub struct Session {
    /// Public key of the owner.
    ///
    /// The owner is the initiator that created
    /// this session.
    owner_key: Vec<u8>,

    /// Public keys of the other session participants.
    participant_keys: HashSet<Vec<u8>>,

    /// Connections between peers established in this
    /// session context.
    connections: HashSet<(Vec<u8>, Vec<u8>)>,

    /// Last access time so the server can reap
    /// stale sessions.
    last_access: SystemTime,
}

impl Session {
    /// Get all participant's public keys
    pub fn public_keys(&self) -> Vec<&[u8]> {
        let mut keys = vec![self.owner_key.as_slice()];
        let mut participants: Vec<_> = self
            .participant_keys
            .iter()
            .map(|k| k.as_slice())
            .collect();
        keys.append(&mut participants);
        keys
    }

    /// Register a connection between peers.
    pub fn register_connection(
        &mut self,
        peer: Vec<u8>,
        other: Vec<u8>,
    ) {
        self.connections.insert((peer, other));
    }

    /// Determine if this session is active.
    ///
    /// A session is active when all participants have created
    /// their peer connections.
    pub fn is_active(&self) -> bool {
        let all_participants = self.public_keys();

        fn check_connection(
            connections: &HashSet<(Vec<u8>, Vec<u8>)>,
            peer: &[u8],
            all: &[&[u8]],
        ) -> bool {
            for key in all {
                if key == &peer {
                    continue;
                }
                // We don't know the order the connections
                // were established so check both.
                let left =
                    connections.get(&(peer.to_vec(), key.to_vec()));
                let right =
                    connections.get(&(key.to_vec(), peer.to_vec()));
                let is_connected = left.is_some() || right.is_some();
                if !is_connected {
                    return false;
                }
            }
            true
        }

        for key in &all_participants {
            let is_connected_others = check_connection(
                &self.connections,
                key,
                all_participants.as_slice(),
            );
            if !is_connected_others {
                return false;
            }
        }

        true
    }
}

/// Manages a collection of sessions.
#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    /// Create a new session.
    pub fn new_session(
        &mut self,
        owner_key: Vec<u8>,
        participant_keys: Vec<Vec<u8>>,
    ) -> SessionId {
        let session_id = SessionId::new_v4();
        let session = Session {
            owner_key,
            participant_keys: participant_keys.into_iter().collect(),
            connections: Default::default(),
            last_access: SystemTime::now(),
        };
        self.sessions.insert(session_id, session);
        session_id
    }

    /// Get a session.
    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Get a mutable session.
    pub fn get_session_mut(
        &mut self,
        id: &SessionId,
    ) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Remove a session.
    pub fn remove_session(
        &mut self,
        id: &SessionId,
    ) -> Option<Session> {
        self.sessions.remove(id)
    }

    /// Retrieve and update the last access time for a session.
    pub fn touch_session(
        &mut self,
        id: &SessionId,
    ) -> Option<&Session> {
        if let Some(session) = self.sessions.get_mut(id) {
            session.last_access = SystemTime::now();
            Some(&*session)
        } else {
            None
        }
    }

    /// Get the keys of sessions that have expired.
    pub fn expired_keys(&self, timeout: u64) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|(_, v)| {
                let now = SystemTime::now();
                let ttl = Duration::from_millis(timeout * 1000);
                if let Some(current) = v.last_access.checked_add(ttl)
                {
                    current < now
                } else {
                    false
                }
            })
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    }
}

/// Request to create a new session.
///
/// Do no include the public key of the initiator as it
/// is automatically added as the session *owner*.
#[derive(Default, Debug)]
pub struct SessionRequest {
    /// Public keys of the session participants.
    pub participant_keys: Vec<Vec<u8>>,
}

/// Response from creating new session.
#[derive(Default, Debug, Clone)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: SessionId,
    /// Public keys of all participants.
    pub all_participants: Vec<Vec<u8>>,
}

impl SessionState {
    /// Get the connections a peer should make.
    pub fn connections(&self, own_key: &[u8]) -> &[Vec<u8>] {
        if self.all_participants.is_empty() {
            return &[];
        }

        if let Some(position) =
            self.all_participants.iter().position(|k| k == own_key)
        {
            if position < self.all_participants.len() - 1 {
                &self.all_participants[position + 1..]
            } else {
                &[]
            }
        } else {
            &[]
        }
    }
}
