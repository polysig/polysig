use crate::protocols::types::KeyShare;
use napi_derive::napi;
use polysig_driver::{
    self as driver,
    synedrion::{self, ecdsa},
};
use serde::{Deserialize, Serialize};

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

impl TryFrom<ThresholdKeyShare> for KeyShare {
    type Error = polysig_protocol::Error;

    fn try_from(
        value: ThresholdKeyShare,
    ) -> Result<Self, Self::Error> {
        let key_share: driver::KeyShare = (&value).try_into()?;
        Ok(key_share.into())
    }
}

impl TryFrom<KeyShare> for ThresholdKeyShare {
    type Error = polysig_protocol::Error;

    fn try_from(value: KeyShare) -> Result<Self, Self::Error> {
        let key_share: driver::KeyShare = value.into();
        Ok((&key_share).try_into()?)
    }
}