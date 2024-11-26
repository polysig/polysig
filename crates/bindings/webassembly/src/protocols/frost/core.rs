macro_rules! frost_impl {
    ($name:ident) => {
        /// FROST protocol.
        #[wasm_bindgen]
        pub struct $name {
            options: polysig_client::SessionOptions,
            key_share: ThresholdKeyShare,
        }

        #[wasm_bindgen]
        impl $name {
            /// Create a FROST protocol.
            #[wasm_bindgen(constructor)]
            pub fn new(
                options: JsValue,
                key_share: JsValue,
            ) -> Result<$name, JsError> {
                let options: SessionOptions =
                    serde_wasm_bindgen::from_value(options)?;
                let key_share: KeyShare =
                    serde_wasm_bindgen::from_value(key_share)?;
                let key_share: ThresholdKeyShare =
                    (&key_share).try_into().map_err(JsError::from)?;
                Ok(Self { options, key_share })
            }

            /// Distributed key generation.
            pub async fn dkg(
                options: JsValue,
                party: JsValue,
                signer: Vec<u8>,
                identifiers: Vec<u16>,
            ) -> Result<JsValue, JsError> {
                let options: SessionOptions =
                    serde_wasm_bindgen::from_value(options)?;

                tracing::info!("decoding the party: {:#?}", party);
                let party: PartyOptions =
                    serde_wasm_bindgen::from_value(party)?;

                tracing::info!("party decoding completed!!!!");

                let signer: SigningKey = into_signing_key(signer)?;
                let verifier = signer.verifying_key().clone();

                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(JsError::from)?;

                let mut ids: Vec<Identifier> =
                    Vec::with_capacity(identifiers.len());
                for id in identifiers {
                    ids.push(id.try_into()?);
                }

                let fut = async move {
                    let key_share =
                        dkg(options, participant, ids).await?;

                    let key_share: KeyShare = (&key_share)
                        .try_into()
                        .map_err(JsError::from)?;

                    Ok(serde_wasm_bindgen::to_value(&key_share)?)
                };
                Ok(future_to_promise(fut).into())
            }

            /// Sign a message.
            pub async fn sign(
                &self,
                party: JsValue,
                signer: Vec<u8>,
                identifiers: Vec<u16>,
                message: Vec<u8>,
            ) -> Result<JsValue, JsError> {
                let options = self.options.clone();
                let party: PartyOptions =
                    serde_wasm_bindgen::from_value(party)?;
                let signer: SigningKey = into_signing_key(signer)?;
                let verifier = signer.verifying_key().clone();
                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(JsError::from)?;

                let mut ids = Vec::with_capacity(identifiers.len());
                for id in identifiers {
                    ids.push(id.try_into()?);
                }

                let key_share = self.key_share.clone();
                let fut = async move {
                    let signature = sign(
                        options,
                        participant,
                        ids,
                        key_share,
                        message,
                    )
                    .await?;
                    Ok(serde_wasm_bindgen::to_value(&signature)?)
                };
                Ok(future_to_promise(fut).into())
            }
        }
    };
}

pub(crate) use frost_impl;
