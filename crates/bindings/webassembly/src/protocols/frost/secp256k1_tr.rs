//! FROST Secp256k1 Taproot protocol.
use polysig_client::{
    frost::secp256k1_tr::{dkg, sign},
    SessionOptions,
};
use polysig_driver::{
    frost::secp256k1_tr::{
        self as frost, Identifier, Participant, PartyOptions,
        SigningKey,
    },
    KeyShare,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Threshold key share for FROST Secp256k1 Taproot.
pub type ThresholdKeyShare = frost::KeyShare;

fn into_signing_key(value: Vec<u8>) -> Result<SigningKey, JsError> {
    Ok(SigningKey::from_bytes(&value)?)
}

super::core::frost_impl!(FrostSecp256K1TrProtocol);
