//! Distributed key generation for FROST Secp256k1 Taproot.
use crate::{Error, NetworkTransport, Result, Transport};
use polysig_protocol::{hex, Parameters, SessionState};

use polysig_driver::{
    frost::secp256k1_tr::{DkgDriver as FrostDriver, KeyShare},
    frost_secp256k1_tr::Identifier,
};

/// Distributed key generation driver for FROST Secp256k1 Taproot
pub type DkgDriver = crate::protocols::frost::core::dkg::DkgDriver<
    FrostDriver,
    KeyShare,
>;

/// Create a new FROST Secp256k1 Taproot DKG driver.
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
