//! Drivers to run multi-party computation protocols to completion
//! and single-party signer implementations.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
pub mod signers;

mod error;

#[cfg(feature = "frost")]
pub mod frost;

#[cfg(any(feature = "ecdsa", feature = "cggmp"))]
pub mod recoverable_signature;

#[cfg(any(feature = "cggmp", feature = "frost"))]
mod protocol;

#[cfg(any(feature = "cggmp", feature = "frost"))]
pub use protocol::*;

#[cfg(feature = "cggmp")]
pub use synedrion::{self, bip32};

#[cfg(feature = "frost-ed25519")]
pub use frost_ed25519;

#[cfg(feature = "frost-secp256k1-tr")]
pub use frost_secp256k1_tr;

#[cfg(any(
    feature = "cggmp",
    feature = "ecdsa",
    feature = "schnorr",
    feature = "frost-secp256k1-tr"
))]
pub use k256;

pub use error::Error;

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "cggmp")]
pub mod cggmp;

pub use sha3;

#[cfg(any(feature = "ecdsa", feature = "cggmp"))]
#[doc(hidden)]
/// Compute the address of an uncompressed public key (65 bytes).
pub fn address(public_key: &[u8]) -> String {
    use polysig_protocol::hex;
    use sha3::{Digest, Keccak256};
    // Remove the leading 0x04
    let bytes = &public_key[1..];
    let digest = Keccak256::digest(bytes);
    let final_bytes = &digest[12..];
    format!("0x{}", hex::encode(final_bytes))
}
