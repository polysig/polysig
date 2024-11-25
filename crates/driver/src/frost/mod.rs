//! FROST protocol implementations.
mod error;

#[cfg(feature = "frost")]
pub(crate) mod core;

#[cfg(feature = "frost-ed25519")]
pub mod ed25519;

#[cfg(feature = "frost-secp256k1-tr")]
pub mod secp256k1_tr;

pub use error::Error;

/// Result type for the FROST protocol.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const ROUND_1: u8 = 1;
pub(crate) const ROUND_2: u8 = 2;
pub(crate) const ROUND_3: u8 = 3;
