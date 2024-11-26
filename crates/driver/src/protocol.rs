//! Types for the protocol drivers.

use crate::{Error, Result};
use polysig_protocol::{Keypair, PartyNumber, RoundNumber};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Generic threshold key share encoded as a PEM.
///
/// The actual threshold key share struct internally
/// uses `BTreeMap` which when passed over the webassembly
/// bindings will be converted to a Javascript `Map` however
/// the `Map` type is not natively supported in `JSON.stringify`
/// and `JSON.parse` without implementing custom replacer and
/// reviver functions which is cumbersome.
///
/// Therefore, to make sharing threshold key shares across the
/// Javacript/Webassembly bindings more ergonomic we first encode
/// the key share to JSON and then encode as a PEM.
///
/// A version number is included to allow us to recognize changes
/// in the upstream library `ThresholdKeyShare` struct.
#[derive(Serialize, Deserialize)]
pub struct KeyShare {
    /// Protocol version.
    pub version: u16,
    /// PEM-encoded key share contents.
    pub contents: String,
}

/// Keys for a protocol participant.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyKeys {
    /// Noise transport keypair.
    pub encrypt: Keypair,
    /// Signing key.
    pub sign: Keypair,
}

/// Information about the current found which
/// can be retrieved from a driver.
#[derive(Debug)]
pub struct RoundInfo {
    /// Whether the round is ready to be finalized.
    pub can_finalize: bool,
    /// Whether the round is an echo round.
    pub is_echo: bool,
    /// Round number.
    pub round_number: u8,
}

/// Trait for implementations that drive
/// protocol to completion.
pub trait ProtocolDriver {
    /// Error type for results.
    type Error: std::error::Error
        + std::fmt::Debug
        + Send
        + Sync
        + From<polysig_protocol::Error>
        + 'static;

    /// Outgoing message type.
    type Message: std::fmt::Debug
        + Round
        + Serialize
        + DeserializeOwned;

    /// Output when the protocol is completed.
    type Output;

    /// Handle an incoming message.
    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> std::result::Result<(), Self::Error>;

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> std::result::Result<Vec<Self::Message>, Self::Error>;

    /// Information about the current round for the driver.
    fn round_info(
        &self,
    ) -> std::result::Result<RoundInfo, Self::Error>;

    /// Try to finalize a round if the protocol is completed
    /// the result is returned.
    ///
    /// Must check with `can_finalize()` first.
    fn try_finalize_round(
        &mut self,
    ) -> std::result::Result<Option<Self::Output>, Self::Error>;
}

/// Trait for round messages.
pub trait Round: Send + Sync {
    /// Round number.
    #[allow(dead_code)]
    fn round_number(&self) -> RoundNumber;

    /// Receiver for a message.
    fn receiver(&self) -> &PartyNumber;
}

/// Round message with additional meta data.
#[derive(Debug, Serialize, Deserialize)]
pub struct RoundMessage<Body, Verifier>
where
    Body: Send + Sync,
{
    pub(crate) round: RoundNumber,
    pub(crate) sender: Verifier,
    pub(crate) receiver: PartyNumber,
    pub(crate) body: Body,
}

impl<Body, Verifier> RoundMessage<Body, Verifier>
where
    Body: Send + Sync,
    Verifier: Serialize + Send + Sync + DeserializeOwned,
{
    /// Consume this message into the sender and body.
    #[allow(dead_code)]
    pub fn into_body(self) -> (Body, Verifier) {
        (self.body, self.sender)
    }
}

impl<Body, Verifier> Round for RoundMessage<Body, Verifier>
where
    Body: Send + Sync,
    Verifier: Serialize + Send + Sync + DeserializeOwned,
{
    fn round_number(&self) -> RoundNumber {
        self.round
    }

    fn receiver(&self) -> &PartyNumber {
        &self.receiver
    }
}

/// Participant in a protocol session.
#[derive(Clone)]
pub struct Participant<Signer, Verifier> {
    /// Signing key for this participant.
    signing_key: Signer,
    /// Options for this participant.
    party: PartyOptions<Verifier>,
}

impl<Signer, Verifier> Participant<Signer, Verifier>
where
    Verifier: PartialEq + std::fmt::Debug,
{
    /// Create a new participant.
    pub fn new(
        signing_key: Signer,
        verifying_key: Verifier,
        party: PartyOptions<Verifier>,
    ) -> Result<Self> {
        if party
            .verifiers()
            .into_iter()
            .find(|v| *v == &verifying_key)
            .is_none()
        {
            return Err(Error::NotVerifyingParty);
        }
        Ok(Self { signing_key, party })
    }

    /// Participant signing key.
    pub fn signing_key(&self) -> &Signer {
        &self.signing_key
    }

    /// Participant party information.
    pub fn party(&self) -> &PartyOptions<Verifier> {
        &self.party
    }
}

/// Options for a party participating in a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions<Verifier> {
    /// Encryption public key for this party.
    public_key: Vec<u8>,
    /// Encryption public keys of all participants including this one.
    participants: Vec<Vec<u8>>,
    /// Whether this party is the session initiator.
    ///
    /// The initiator is responsible for disposing of a
    /// session once a protocol completes.
    is_initiator: bool,
    /// Index of the party in the participants list.
    party_index: usize,
    /// Verifying keys for all participants.
    verifiers: Vec<Verifier>,
}

impl<Verifier> PartyOptions<Verifier> {
    /// Create new party participant options.
    pub fn new(
        public_key: Vec<u8>,
        participants: Vec<Vec<u8>>,
        is_initiator: bool,
        verifiers: Vec<Verifier>,
    ) -> Result<Self> {
        let party_index = participants
            .iter()
            .position(|v| v == &public_key)
            .ok_or(Error::NotVerifyingParty)?;

        if participants.len() != verifiers.len() {
            return Err(Error::ParticipantVerifierLength(
                participants.len(),
                verifiers.len(),
            ));
        }

        Ok(Self {
            public_key,
            participants,
            is_initiator,
            party_index,
            verifiers,
        })
    }

    /// Public key of this participant.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Participant public keys.
    pub fn participants(&self) -> &[Vec<u8>] {
        self.participants.as_slice()
    }

    /// Index of this participant.
    pub fn party_index(&self) -> usize {
        self.party_index
    }

    /// Whether this party is the session initator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Participant verifying keys.
    pub fn verifiers(&self) -> &[Verifier] {
        self.verifiers.as_slice()
    }
}
