//! Recoverable signature for ECDSA.
use k256::ecdsa::{RecoveryId, Signature};
use serde::{Deserialize, Serialize};
use synedrion::SchemeParams;

/// Recoverable signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverableSignature {
    /// Signature bytes.
    pub bytes: Vec<u8>,
    /// Recovery identifier.
    pub recovery_id: u8,
}

impl<P: SchemeParams> From<(Signature, RecoveryId)>
    for RecoverableSignature<P>
{
    fn from(value: (Signature, RecoveryId)) -> Self {
        Self {
            bytes: value.0.to_vec(),
            recovery_id: value.1.into(),
        }
    }
}

impl TryFrom<&RecoverableSignature> for (Signature, RecoveryId) {
    type Error = crate::Error;

    fn try_from(
        value: &RecoverableSignature,
    ) -> Result<Self, Self::Error> {
        Ok((
            Signature::from_slice(&value.bytes)?,
            value.recovery_id.try_into()?,
        ))
    }
}

impl TryFrom<RecoverableSignature> for (Signature, RecoveryId) {
    type Error = crate::Error;

    fn try_from(
        value: RecoverableSignature,
    ) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

#[cfg(feature = "cggmp")]
impl From<synedrion::RecoverableSignature> for RecoverableSignature {
    fn from(value: synedrion::RecoverableSignature) -> Self {
        value.to_backend().into()
    }
}
