//! Driver for the FROST Ed25519 protocol.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
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
pub type Signature = frost_ed25519::Signature;

/// Identifier for this protocol.
pub type Identifier = frost_ed25519::Identifier;

const TAG: &str = "FROST ED25519 KEY SHARE";
const PEM_VERSION: u16 = 1;

super::core::key_share_pem!();
