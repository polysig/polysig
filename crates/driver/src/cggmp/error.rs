use k256::ecdsa::VerifyingKey;
use thiserror::Error;

/// Errors generated by the protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated by the CGGMP protocol library
    /// on a local node.
    #[error("{0}")]
    LocalError(String),

    /// Error generated by the CGGMP protocol library
    /// on a remote node.
    #[error("{0}")]
    RemoteError(String),

    /// Signature verification failed.
    #[error("failed to verify generated signature")]
    VerifySignature,

    /// Could not locate ack for key init phase.
    #[error("could not find an ACK for key init phase")]
    NoKeyInitAck,

    /// Attempt to finish a protocol when another round is expected.
    #[error("protocol is not finished, another round is available")]
    NotFinished,

    /// Protocol library errors.
    #[error(transparent)]
    Protocol(#[from] polysig_protocol::Error),

    /// Error generated converting integers.
    #[error(transparent)]
    FromInt(#[from] std::num::TryFromIntError),

    /// BIP32 library error.
    #[error(transparent)]
    Bip32(#[from] synedrion::bip32::Error),
}

impl From<synedrion::sessions::LocalError> for Error {
    fn from(value: synedrion::sessions::LocalError) -> Self {
        Error::LocalError(value.to_string())
    }
}

impl From<synedrion::sessions::RemoteError<VerifyingKey>> for Error {
    fn from(
        value: synedrion::sessions::RemoteError<VerifyingKey>,
    ) -> Self {
        Error::RemoteError(format!("{:#?}", value.error))
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(value: Error) -> Self {
        let s = value.to_string();
        wasm_bindgen::JsValue::from_str(&s)
    }
}
