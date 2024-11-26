//! Generate Schnorr signatures compatible with Bitcoin
//! Taproot (BIP 340).
use crate::Result;
use k256::schnorr::{
    signature::{hazmat::PrehashSigner, Signer, Verifier},
    SigningKey,
};
use rand::rngs::OsRng;
use std::borrow::Cow;

pub use k256::schnorr::{Signature, VerifyingKey};

/// Create a signer for Taproot BIP-340 Schnorr signatures.
pub struct SchnorrSigner<'a> {
    signing_key: Cow<'a, SigningKey>,
}

impl<'a> SchnorrSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: Cow<'a, SigningKey>) -> Self {
        Self { signing_key }
    }

    /// Initialize a signing key from a byte slice.
    pub fn from_slice(signing_key: &[u8]) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(signing_key)?)
    }

    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Attempt to sign the given message digest, returning a
    /// digital signature on success, or an error if something went wrong.
    pub fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        Ok(self.signing_key.sign_prehash(prehash)?)
    }

    /// Compute Schnorr signature.
    ///
    /// # ⚠️  Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving signing pre-hashed messages.
    pub fn sign_raw(
        &self,
        msg_digest: &[u8],
        aux_rand: &[u8; 32],
    ) -> Result<Signature> {
        Ok(self.signing_key.sign_raw(msg_digest, aux_rand)?)
    }

    /// Verifying key for this signer.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Verify a Schnorr signaature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        Ok(self.verifying_key().verify(message, signature)?)
    }
    /// Verify a Schnorr signaature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving verifying pre-hashed messages, or "raw" messages where the
    /// message is not hashed at all prior to being used to generate the
    /// Schnorr signature.
    pub fn verify_raw(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        Ok(self.verifying_key().verify_raw(message, signature)?)
    }
}
