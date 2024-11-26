//! Driver for the FROST Secp256k1 Taproot protocol.

use polysig_driver::{
    frost::secp256k1_tr::{KeyShare, Participant, Signature},
    frost_secp256k1_tr::Identifier,
};

use crate::{
    new_client,
    protocols::frost::core::{
        dkg::frost_dkg_impl, sign::frost_sign_impl,
    },
    wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, NetworkTransport, SessionHandler,
    SessionInitiator, SessionOptions, SessionParticipant, Transport,
};

mod dkg;
mod sign;

frost_dkg_impl!();
frost_sign_impl!();
