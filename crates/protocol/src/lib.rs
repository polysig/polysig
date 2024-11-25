//! Relay service protocol types, encoding and helper functions.
//!
//! # Size Limitations
//!
//! The maximum size of a [noise protocol](https://noiseprotocol.org/)
//! message is 65535 and we further limit the size of buffers
//! for encoding to 32KB.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
#![allow(clippy::len_without_is_empty)]

#[doc(hidden)]
pub mod channel;
mod constants;
pub(crate) mod encoding;
mod error;
mod event;
mod keypair;
mod meetings;
mod protocol;
pub mod zlib;

pub use constants::*;
pub use encoding::{decode, encode, VERSION};
pub use error::Error;
pub use event::{Event, JsonMessage};
pub use keypair::*;
pub use meetings::*;
pub use protocol::*;

pub use hex;
pub use http;
pub use log;
pub use pem;
pub use serde_json;
pub use snow;
pub use uuid;

/// Round number.
pub type RoundNumber = std::num::NonZeroU16;

/// Party number.
pub type PartyNumber = std::num::NonZeroU16;

/// Result type for the protocol library.
pub type Result<T> = std::result::Result<T, Error>;
