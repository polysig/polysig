//! Signature generation for FROST Secp256k1 Taproot protocol.
use frost_secp256k1_tr::{
    aggregate,
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU16;

use crate::{
    frost::{Error, Result},
    ProtocolDriver, RoundInfo, RoundMessage,
};

use super::KeyShare;
use crate::frost::{
    core::sign::frost_sign_impl, ROUND_1, ROUND_2, ROUND_3,
};

frost_sign_impl!(
    SigningCommitments,
    SigningNonces,
    SignatureShare,
    SigningPackage,
    Identifier,
    Signature,
    round1,
    round2,
    aggregate
);
