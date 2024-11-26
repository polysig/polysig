//! Signature generation for FROST Ed25519.
use polysig_driver::{
    frost::ed25519::{KeyShare, SignatureDriver as FrostDriver},
    frost_ed25519::{Identifier, Signature},
};

use crate::{Error, NetworkTransport, Result, Transport};
use polysig_protocol::{hex, SessionState};

/// Signature generation driver for FROST Ed25519.
pub type SignatureDriver =
    crate::protocols::frost::core::sign::SignatureDriver<
        FrostDriver,
        Signature,
    >;

/// Create a new FROST Ed25519 signature driver.
pub fn new_driver(
    transport: Transport,
    session: SessionState,
    identifiers: Vec<Identifier>,
    min_signers: u16,
    key_share: KeyShare,
    message: Vec<u8>,
) -> Result<SignatureDriver> {
    let party_number = session
        .party_number(transport.public_key())
        .ok_or_else(|| {
        Error::NotSessionParticipant(hex::encode(
            transport.public_key(),
        ))
    })?;

    let driver = FrostDriver::new(
        party_number,
        identifiers,
        min_signers,
        key_share,
        message,
    )?;

    Ok(SignatureDriver::new(
        transport,
        session,
        party_number,
        driver,
    ))
}
