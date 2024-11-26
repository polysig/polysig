//! Driver for the FROST Ed25519 protocol.
use polysig_driver::{
    frost::ed25519::{KeyShare, Participant, Signature},
    frost_ed25519::Identifier,
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
