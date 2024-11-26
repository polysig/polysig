use super::dkg::run_dkg;
use anyhow::Result;
use polysig_client::{
    frost::secp256k1_tr::sign, ServerOptions, SessionOptions,
};
use polysig_driver::{
    frost::secp256k1_tr::{KeyShare, Participant, PartyOptions},
    frost_secp256k1_tr::{keys, Identifier},
    k256::schnorr::{SigningKey, VerifyingKey},
};

use polysig_protocol::{Keypair, Parameters};
use std::collections::BTreeMap;

use crate::protocols::frost_core::{
    make_signing_message, sign::frost_dkg_sign,
};

frost_dkg_sign!();
