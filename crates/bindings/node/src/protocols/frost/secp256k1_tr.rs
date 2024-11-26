//! FROST Secp256k1 Taproot protocol.
use crate::protocols::types::{KeyShare, SessionOptions};
use anyhow::Error;
use napi::bindgen_prelude::Result;
use napi_derive::napi;
use polysig_client::frost::secp256k1_tr::{dkg, sign};
use polysig_driver::{
    self as driver,
    frost::secp256k1_tr::{
        self as frost, Participant,
        PartyOptions as ProtocolPartyOptions,
        SigningKey as ProtocolSigningKey,
        VerifyingKey as ProtocolVerifyingKey,
    },
};
use serde::{Deserialize, Serialize};

/// Threshold key share for FROST Secp256k1 Taproot.
pub type ThresholdKeyShare = frost::KeyShare;

use super::core::{frost_impl, frost_types};

/// Protocol signing key.
#[napi(object)]
pub struct SigningKey {
    /// Signing key bytes.
    pub bytes: Vec<u8>,
}

impl TryFrom<SigningKey> for frost::SigningKey {
    type Error = napi::Error;

    fn try_from(
        value: SigningKey,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(ProtocolSigningKey::from_bytes(value.bytes.as_slice())
            .map_err(Error::new)?)
    }
}

frost_types!();
frost_impl!(FrostSecp256K1TrProtocol);
