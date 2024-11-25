//! Distributed key generation for FROST Ed25519.
use crate::{Error, NetworkTransport, Result, Transport};
use polysig_protocol::{hex, Parameters, SessionState};

use polysig_driver::{
    frost::ed25519::{DkgDriver as FrostDriver, KeyShare},
    frost_ed25519::Identifier,
};

/// Distributed key generation driver for FROST Ed25519
pub type DkgDriver = crate::protocols::frost::core::dkg::DkgDriver<
    FrostDriver,
    KeyShare,
>;

/// Create a new FROST Ed25519 DKG driver.
pub fn new_driver(
    transport: Transport,
    session: SessionState,
    params: Parameters,
    identifiers: Vec<Identifier>,
) -> Result<DkgDriver> {
    let party_number = session
        .party_number(transport.public_key())
        .ok_or_else(|| {
        Error::NotSessionParticipant(hex::encode(
            transport.public_key(),
        ))
    })?;

    let driver = FrostDriver::new(party_number, params, identifiers)?;

    Ok(DkgDriver::new(transport, session, party_number, driver))
}
