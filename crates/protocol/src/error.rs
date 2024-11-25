use thiserror::Error;

/// Errors generated by the relay protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated a buffer is too large.
    #[error("buffer exceeds maximum size {0}")]
    MaxBufferSize(usize),

    /// Error generated when encoding identity bytes are invalid.
    #[error("encoding identity bytes are invalid")]
    BadEncodingIdentity,

    /// Error generated when encoding versions are mismatched.
    #[error("encoding version is not supported, expecting version {0} but got version {1}")]
    EncodingVersion(u16, u16),

    /// Error generated decoding the kind for an encoding is invalid.
    #[error("invalid encoding kind identifier {0}")]
    EncodingKind(u8),

    /// Error generated when the noise pattern in a PEM does not
    /// match the pattern in use by the protocol.
    #[error(r#"noise protocol pattern mismatch, expecting "{0}""#)]
    PatternMismatch(String),

    /// Error generated when the PEM encoding does not match
    /// the expected format.
    #[error("encoding in PEM is invalid")]
    BadKeypairPem,

    /// Error generated when a node expects to be in the transport
    /// protocol state.
    #[error("not transport protocol state")]
    NotTransportState,

    /// Error generated when a signing key type is not recognized.
    #[error("not a recognized key type: {0}")]
    UnknownKeyType(String),

    /// Error generated when a PEM tag is wrong.
    #[error("wrong PEM tag, expected '{0}' but got '{1}'")]
    PemTag(String, String),

    /// Error generated by input/output.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated converting to slices.
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),

    /// Error generated by the noise protocol library.
    #[error(transparent)]
    Snow(#[from] snow::error::Error),

    /// Error generated decoding PEM data.
    #[error(transparent)]
    Pem(#[from] pem::PemError),

    /// Error generated serializing or deserializing JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
