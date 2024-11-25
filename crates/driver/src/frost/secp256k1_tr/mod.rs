//! Driver for the FROST Secp256k1 Taproot protocol.
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
pub use k256::schnorr::{SigningKey, VerifyingKey};
use polysig_protocol::pem;

mod dkg;
mod sign;

pub use dkg::DkgDriver;
pub use sign::SignatureDriver;

/// Participant in the protocol.
pub type Participant = crate::Participant<SigningKey, VerifyingKey>;

/// Options for each party.
pub type PartyOptions = crate::PartyOptions<VerifyingKey>;

/// Key share for this protocol.
pub type KeyShare = (KeyPackage, PublicKeyPackage);
/// Signature for this protocol.
pub type Signature = frost_secp256k1_tr::Signature;

const TAG: &str = "FROST SECP256K1-TR KEY SHARE";
const PEM_VERSION: u16 = 1;

super::core::key_share_pem!();
