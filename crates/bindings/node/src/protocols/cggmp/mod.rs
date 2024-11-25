//! Bindings for the CGGMP protocol.
use anyhow::Error;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use polysig_driver::cggmp::Participant;
use polysig_driver::synedrion::{
    ecdsa::{self, SigningKey},
    SessionId,
};
use polysig_protocol::{hex, PATTERN};
use std::collections::BTreeSet;

use super::types::{RecoverableSignature, SessionOptions};

mod types;

use types::{
    KeyShare, Params, PartyOptions, ThresholdKeyShare, VerifyingKey,
};

/// CGGMP protocol.
#[napi]
pub struct CggmpProtocol {
    options: polysig_client::SessionOptions,
    key_share: ThresholdKeyShare,
}

#[napi]
impl CggmpProtocol {
    /// Create a CGGMP protocol.
    #[napi(constructor)]
    pub fn new(
        options: SessionOptions,
        key_share: KeyShare,
    ) -> Result<CggmpProtocol> {
        let options: polysig_client::SessionOptions =
            options.try_into().map_err(Error::new)?;
        let key_share: ThresholdKeyShare =
            key_share.try_into().map_err(Error::new)?;
        Ok(Self { options, key_share })
    }

    /// Verifying key for this signer.
    #[napi(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.key_share.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Compute the Ethereum address for the verifying key.
    #[napi]
    pub fn address(&self) -> String {
        let public_key = self
            .key_share
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        polysig_driver::address(&public_key)
    }

    /// Distributed key generation.
    #[napi]
    pub async fn dkg(
        options: SessionOptions,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
    ) -> Result<KeyShare> {
        let options: polysig_client::SessionOptions =
            options.try_into().map_err(Error::new)?;

        let party: polysig_driver::cggmp::PartyOptions =
            party.try_into().map_err(Error::new)?;

        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::new)?;
        let verifier = signer.verifying_key().clone();

        let participant = Participant::new(signer, verifier, party)
            .map_err(Error::new)?;
        let key_share = polysig_client::cggmp::dkg::<Params>(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
        )
        .await
        .map_err(Error::new)?;

        let key_share: KeyShare =
            key_share.try_into().map_err(Error::new)?;
        Ok(key_share)
    }

    /// Sign a message.
    #[napi]
    pub async fn sign(
        &self,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        message: String,
    ) -> Result<RecoverableSignature> {
        let options = self.options.clone();
        let party: polysig_driver::cggmp::PartyOptions =
            party.try_into().map_err(Error::new)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::new)?;
        let verifier = signer.verifying_key().clone();
        let message = hex::decode(&message).map_err(Error::new)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(Error::new)?;
        let participant = Participant::new(signer, verifier, party)
            .map_err(Error::new)?;

        let mut selected_parties = BTreeSet::new();
        selected_parties
            .extend(participant.party().verifiers().iter());
        let key_share =
            self.key_share.to_key_share(&selected_parties);

        let signature = polysig_client::cggmp::sign(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
            &key_share,
            &message,
        )
        .await
        .map_err(Error::new)?;

        let signature: RecoverableSignature =
            signature.try_into().map_err(Error::new)?;
        Ok(signature)
    }

    /// Reshare key shares.
    #[napi]
    pub async fn reshare(
        &self,
        // options: SessionOptions,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: VerifyingKey,
        key_share: Option<KeyShare>,
        old_threshold: i64,
        new_threshold: i64,
    ) -> Result<KeyShare> {
        let options = self.options.clone();
        let party: polysig_driver::cggmp::PartyOptions =
            party.try_into().map_err(Error::new)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::new)?;
        let verifier = signer.verifying_key().clone();

        let account_verifying_key: ecdsa::VerifyingKey =
            account_verifying_key.try_into().map_err(Error::new)?;

        let key_share: Option<ThresholdKeyShare> =
            if let Some(key_share) = key_share {
                Some(key_share.try_into().map_err(Error::new)?)
            } else {
                None
            };
        let participant = Participant::new(signer, verifier, party)
            .map_err(Error::new)?;

        let key_share = polysig_client::cggmp::reshare(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
            account_verifying_key,
            key_share,
            old_threshold as usize,
            new_threshold as usize,
        )
        .await
        .map_err(Error::new)?;

        let key_share: KeyShare =
            key_share.try_into().map_err(Error::new)?;
        Ok(key_share)
    }

    /// Generate a BIP32 derived child key.
    #[napi(js_name = "deriveBip32")]
    pub fn derive_bip32(
        &self,
        derivation_path: String,
    ) -> std::result::Result<KeyShare, napi::JsError> {
        use polysig_driver::bip32::DerivationPath;
        let derivation_path: DerivationPath =
            derivation_path.parse().map_err(Error::new)?;
        let child_key = polysig_driver::cggmp::derive_bip32(
            &self.key_share,
            &derivation_path,
        )
        .map_err(Error::new)?;
        Ok(child_key.try_into().map_err(Error::new)?)
    }

    /// Generate a PEM-encoded keypair for the noise protocol.
    ///
    /// Uses the default noise protocol parameters
    /// if no pattern is given.
    #[napi(js_name = "generateKeypair")]
    pub fn generate_keypair(
        pattern: Option<String>,
        env: Env,
    ) -> std::result::Result<napi::JsUnknown, JsError> {
        let pattern = pattern.unwrap_or_else(|| PATTERN.to_owned());
        let keypair = polysig_protocol::Keypair::new_params(
            pattern.parse().map_err(Error::new)?,
        )
        .map_err(Error::new)?;
        let public_key = hex::encode(keypair.public_key());
        let pem = keypair.encode_pem();
        Ok(env.to_js_value(&(pem, public_key)).map_err(Error::new)?)
    }
}
