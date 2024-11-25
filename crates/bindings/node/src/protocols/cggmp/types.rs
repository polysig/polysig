use napi_derive::napi;
use polysig_driver::synedrion::{self, ecdsa};
use polysig_protocol as protocol;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(not(debug_assertions))]
pub(super) type Params = synedrion::ProductionParams;
#[cfg(debug_assertions)]
pub(super) type Params = synedrion::TestParams;

pub(super) type ThresholdKeyShare =
    synedrion::ThresholdKeyShare<Params, ecdsa::VerifyingKey>;

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyingKey {
    pub bytes: Vec<u8>,
}

impl TryFrom<VerifyingKey> for ecdsa::VerifyingKey {
    type Error = polysig_driver::Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Ok(ecdsa::VerifyingKey::from_sec1_bytes(&value.bytes)?)
    }
}

/// Keypair for the noise transport.
#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub r#type: String,
}

impl TryFrom<Keypair> for protocol::Keypair {
    type Error = polysig_driver::Error;

    fn try_from(value: Keypair) -> Result<Self, Self::Error> {
        Ok(protocol::Keypair::new(
            value.private,
            value.public,
            value.r#type.parse()?,
        ))
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Parameters {
    pub parties: u16,
    pub threshold: u16,
}

impl From<Parameters> for polysig_protocol::Parameters {
    fn from(value: Parameters) -> Self {
        polysig_protocol::Parameters {
            parties: value.parties,
            threshold: value.threshold,
        }
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOptions {
    pub server_url: String,
    pub server_public_key: Vec<u8>,
    pub pattern: Option<String>,
}

impl From<ServerOptions> for polysig_client::ServerOptions {
    fn from(value: ServerOptions) -> Self {
        polysig_client::ServerOptions {
            server_url: value.server_url,
            server_public_key: value.server_public_key,
            pattern: value.pattern,
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionOptions {
    pub keypair: Keypair,
    pub server: ServerOptions,
    pub parameters: Parameters,
}

impl TryFrom<SessionOptions> for polysig_client::SessionOptions {
    type Error = polysig_driver::Error;

    fn try_from(value: SessionOptions) -> Result<Self, Self::Error> {
        Ok(polysig_client::SessionOptions {
            keypair: value.keypair.try_into()?,
            server: value.server.into(),
            parameters: value.parameters.into(),
        })
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions {
    pub public_key: Vec<u8>,
    pub participants: Vec<Vec<u8>>,
    pub is_initiator: bool,
    pub verifiers: Vec<VerifyingKey>,
}

impl TryFrom<PartyOptions> for polysig_driver::cggmp::PartyOptions {
    type Error = polysig_driver::Error;

    fn try_from(value: PartyOptions) -> Result<Self, Self::Error> {
        let mut verifiers = Vec::with_capacity(value.verifiers.len());
        for verifier in value.verifiers {
            verifiers.push(verifier.try_into()?);
        }
        Ok(polysig_driver::PartyOptions::new(
            value.public_key,
            value.participants,
            value.is_initiator,
            verifiers,
        )?)
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyShare {
    // Encoded as a JSON string as we can't access the inner
    // state of synedrion::ThresholdKeyShare directly
    pub inner: String,
}

impl TryFrom<ThresholdKeyShare> for KeyShare {
    type Error = polysig_driver::Error;

    fn try_from(
        value: ThresholdKeyShare,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: serde_json::to_string(&value)?,
        })
    }
}

impl TryFrom<KeyShare> for ThresholdKeyShare {
    type Error = polysig_driver::Error;

    fn try_from(value: KeyShare) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str(&value.inner)?)
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecoverableSignature {
    pub bytes: Vec<u8>,
    pub recovery_id: u8,
}

impl From<RecoverableSignature>
    for polysig_driver::recoverable_signature::RecoverableSignature
{
    fn from(value: RecoverableSignature) -> Self {
        Self {
            bytes: value.bytes,
            recovery_id: value.recovery_id,
        }
    }
}

impl From<polysig_driver::recoverable_signature::RecoverableSignature>
    for RecoverableSignature
{
    fn from(
        value: polysig_driver::recoverable_signature::RecoverableSignature,
    ) -> Self {
        Self {
            bytes: value.bytes,
            recovery_id: value.recovery_id,
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct UserId {
    /// User identifier.
    pub id: Vec<u8>,
}

impl TryFrom<UserId> for protocol::UserId {
    type Error = anyhow::Error;

    fn try_from(value: UserId) -> Result<Self, Self::Error> {
        let buf: [u8; 32] = value.id.as_slice().try_into()?;
        Ok(buf.into())
    }
}

impl From<protocol::UserId> for UserId {
    fn from(value: protocol::UserId) -> Self {
        Self {
            id: value.as_ref().to_vec(),
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeys {
    /// Transport public key.
    pub public_key: Vec<u8>,
    /// Verifiying key.
    pub verifying_key: Vec<u8>,
    /// Optional associated data.
    pub associated_data: Option<Value>,
}

impl From<PublicKeys> for protocol::PublicKeys {
    fn from(value: PublicKeys) -> Self {
        protocol::PublicKeys {
            public_key: value.public_key,
            verifying_key: value.verifying_key,
            associated_data: value.associated_data,
        }
    }
}

impl From<protocol::PublicKeys> for PublicKeys {
    fn from(value: protocol::PublicKeys) -> Self {
        PublicKeys {
            public_key: value.public_key,
            verifying_key: value.verifying_key,
            associated_data: value.associated_data,
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MeetingItem {
    /// User identifiers.
    pub user_id: UserId,
    /// Data for the user.
    pub data: PublicKeys,
}
