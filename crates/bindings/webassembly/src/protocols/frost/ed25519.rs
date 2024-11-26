//! FROST Ed25519 protocol.
use polysig_client::{
    frost::ed25519::{dkg, sign},
    SessionOptions,
};
use polysig_driver::{
    frost::ed25519::{
        self as frost, Identifier, Participant, PartyOptions,
        SigningKey,
    },
    KeyShare,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Threshold key share for FROST Ed25519.
pub type ThresholdKeyShare = frost::KeyShare;

fn into_signing_key(value: Vec<u8>) -> Result<SigningKey, JsError> {
    let bytes: [u8; 32] =
        value.as_slice().try_into().map_err(JsError::from)?;
    Ok(SigningKey::from_bytes(&bytes))
}

super::core::frost_impl!(FrostEd25519Protocol);
