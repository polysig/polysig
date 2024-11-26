use super::dkg::run_dkg;
use anyhow::Result;
use polysig_client::{
    frost::ed25519::sign, ServerOptions, SessionOptions,
};
use polysig_driver::{
    frost::ed25519::{KeyShare, Participant, PartyOptions},
    frost_ed25519::{keys, Identifier},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use polysig_protocol::{Keypair, Parameters};
use std::collections::BTreeMap;

use crate::protocols::frost_core::{
    make_signing_message, sign::frost_dkg_sign,
};

frost_dkg_sign!();
