//! Bindings for the CGGMP protocol.
use polysig_client::SessionOptions;
use polysig_driver::synedrion::{
    self,
    ecdsa::{SigningKey, VerifyingKey},
    SessionId,
};
use polysig_driver::{
    cggmp::{self, Participant},
    KeyShare,
};
use polysig_protocol::hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[cfg(not(debug_assertions))]
type Params = synedrion::ProductionParams;
#[cfg(debug_assertions)]
type Params = synedrion::TestParams;

type ThresholdKeyShare =
    synedrion::ThresholdKeyShare<Params, VerifyingKey>;

/// Options for a party participating in a protocol.
///
/// Required in the bindings to convert the `verifiers`
/// from bytes to verifying keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions {
    public_key: Vec<u8>,
    participants: Vec<Vec<u8>>,
    is_initiator: bool,
    party_index: usize,
    verifiers: Vec<Vec<u8>>,
}

impl TryFrom<PartyOptions> for cggmp::PartyOptions {
    type Error = JsError;

    fn try_from(value: PartyOptions) -> Result<Self, Self::Error> {
        let mut verifiers = Vec::with_capacity(value.verifiers.len());
        for key in &value.verifiers {
            verifiers.push(
                VerifyingKey::from_sec1_bytes(key)
                    .map_err(JsError::from)?,
            );
        }

        Ok(cggmp::PartyOptions::new(
            value.public_key,
            value.participants,
            value.is_initiator,
            verifiers,
        )?)
    }
}

/// CGGMP protocol.
#[wasm_bindgen]
pub struct CggmpProtocol {
    options: SessionOptions,
    key_share: ThresholdKeyShare,
}

#[wasm_bindgen]
impl CggmpProtocol {
    /// Create a CGGMP protocol.
    #[wasm_bindgen(constructor)]
    pub fn new(
        options: JsValue,
        key_share: JsValue,
    ) -> Result<CggmpProtocol, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let key_share: KeyShare =
            serde_wasm_bindgen::from_value(key_share)?;
        let key_share: ThresholdKeyShare =
            (&key_share).try_into().map_err(JsError::from)?;
        Ok(Self { options, key_share })
    }

    /// Verifying key for this signer.
    #[wasm_bindgen(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.key_share.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Compute the Ethereum address for the verifying key.
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
    pub fn dkg(
        options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let participant =
            Participant::new(signer, verifier, party.try_into()?)
                .map_err(JsError::from)?;
        let fut = async move {
            let key_share = polysig_client::cggmp::dkg::<Params>(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
            )
            .await?;

            let key_share: KeyShare =
                (&key_share).try_into().map_err(JsError::from)?;

            Ok(serde_wasm_bindgen::to_value(&key_share)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Sign a message.
    pub fn sign(
        &self,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        message: String,
    ) -> Result<JsValue, JsError> {
        let options = self.options.clone();
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let participant =
            Participant::new(signer, verifier, party.try_into()?)
                .map_err(JsError::from)?;

        let mut selected_parties = BTreeSet::new();
        selected_parties
            .extend(participant.party().verifiers().iter());

        let key_share =
            self.key_share.to_key_share(&selected_parties);

        let message: Vec<u8> =
            hex::decode(&message).map_err(JsError::from)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(JsError::from)?;

        let fut = async move {
            let signature = polysig_client::cggmp::sign(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                &key_share,
                &message,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&signature)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Reshare key shares.
    pub fn reshare(
        &self,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: JsValue,
        key_share: JsValue,
        old_threshold: usize,
        new_threshold: usize,
    ) -> Result<JsValue, JsError> {
        let options = self.options.clone();
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let account_verifying_key: VerifyingKey =
            serde_wasm_bindgen::from_value(account_verifying_key)?;

        let key_share: Option<KeyShare> =
            serde_wasm_bindgen::from_value(key_share)?;
        let key_share: Option<ThresholdKeyShare> =
            if let Some(key_share) = key_share {
                Some((&key_share).try_into().map_err(JsError::from)?)
            } else {
                None
            };

        let participant =
            Participant::new(signer, verifier, party.try_into()?)
                .map_err(JsError::from)?;

        let fut = async move {
            let key_share = polysig_client::cggmp::reshare(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                account_verifying_key,
                key_share,
                old_threshold,
                new_threshold,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&key_share)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Generate a BIP32 derived child key.
    #[wasm_bindgen(js_name = "deriveBip32")]
    pub fn derive_bip32(
        &self,
        derivation_path: String,
    ) -> Result<JsValue, JsError> {
        use polysig_driver::bip32::DerivationPath;

        let derivation_path: DerivationPath =
            derivation_path.parse()?;
        let child_key = polysig_driver::cggmp::derive_bip32(
            &self.key_share,
            &derivation_path,
        )?;

        Ok(serde_wasm_bindgen::to_value(&child_key)?)
    }

    /// Generate an encyption keypair for the noise protocol.
    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair() -> Result<JsValue, JsError> {
        let keypair = polysig_protocol::Keypair::generate()?;
        Ok(serde_wasm_bindgen::to_value(&keypair)?)
    }
}
