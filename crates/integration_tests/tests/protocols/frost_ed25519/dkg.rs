use anyhow::Result;
use ed25519_dalek::SigningKey;
use polysig_client::{
    frost::ed25519::dkg, ServerOptions, SessionOptions,
};
use polysig_driver::frost::ed25519::{
    Identifier, KeyShare, Participant, PartyOptions,
};
use polysig_protocol::{Keypair, Parameters};

use super::make_signers;
use crate::protocols::frost_core::dkg::frost_dkg;

frost_dkg!();
