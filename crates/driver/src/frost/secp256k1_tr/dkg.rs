//! Key generation for FROST Secp256k1 Taproot protocol.
use frost_secp256k1_tr::{
    keys::dkg::{self, part1, part2, part3},
    Identifier,
};
use polysig_protocol::Parameters;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, num::NonZeroU16};

use crate::{
    frost::{Error, Result},
    ProtocolDriver, RoundInfo, RoundMessage,
};

use super::KeyShare;

use crate::frost::{
    core::dkg::frost_dkg_impl, ROUND_1, ROUND_2, ROUND_3,
};

frost_dkg_impl!(
    dkg::round1::Package,
    dkg::round1::SecretPackage,
    dkg::round2::Package,
    dkg::round2::SecretPackage,
    Identifier,
    KeyShare,
    part1,
    part2,
    part3
);
