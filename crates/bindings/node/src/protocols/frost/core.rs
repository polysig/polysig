macro_rules! frost_impl {
    ($name:ident) => {
        /// FROST protocol.
        #[napi]
        pub struct $name {
            options: polysig_client::SessionOptions,
            key_share: ThresholdKeyShare,
        }

        #[napi]
        impl $name {
            /// Create a FROST protocol.
            #[napi(constructor)]
            pub fn new(
                options: SessionOptions,
                key_share: KeyShare,
            ) -> Result<$name> {
                let options: polysig_client::SessionOptions =
                    options.try_into().map_err(Error::new)?;
                let key_share: ThresholdKeyShare =
                    key_share.try_into().map_err(Error::new)?;
                Ok(Self { options, key_share })
            }

            /// Distributed key generation.
            #[napi]
            pub async fn dkg(
                options: SessionOptions,
                party: PartyOptions,
                signer: SigningKey,
                identifiers: Vec<Identifier>,
            ) -> Result<KeyShare> {
                let options: polysig_client::SessionOptions =
                    options.try_into().map_err(Error::new)?;

                let party: ProtocolPartyOptions =
                    party.try_into().map_err(Error::new)?;

                let signer: ProtocolSigningKey = signer.try_into()?;
                let verifier = signer.verifying_key().clone();

                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(Error::new)?;

                let mut ids = Vec::with_capacity(identifiers.len());
                for id in identifiers {
                    ids.push(id.try_into()?);
                }

                let key_share = dkg(options, participant, ids)
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
                signer: SigningKey,
                identifiers: Vec<Identifier>,
                message: String,
            ) -> Result<Signature> {
                let options = self.options.clone();
                let party: ProtocolPartyOptions =
                    party.try_into().map_err(Error::new)?;
                let signer: ProtocolSigningKey = signer.try_into()?;
                let verifier = signer.verifying_key().clone();
                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(Error::new)?;

                let mut ids = Vec::with_capacity(identifiers.len());
                for id in identifiers {
                    ids.push(id.try_into()?);
                }

                let signature = sign(
                    options,
                    participant,
                    ids,
                    self.key_share.clone(),
                    message.as_bytes().to_vec(),
                )
                .await
                .map_err(Error::new)?;

                Ok(signature.try_into()?)
            }
        }
    };
}

macro_rules! frost_types {
    () => {
        #[doc(hidden)]
        #[napi(object)]
        #[derive(Serialize, Deserialize, Debug)]
        pub struct VerifyingKey {
            pub public_key: Vec<u8>,
        }

        impl TryFrom<VerifyingKey> for ProtocolVerifyingKey {
            type Error = napi::Error;

            fn try_from(
                value: VerifyingKey,
            ) -> std::result::Result<Self, Self::Error> {
                let bytes: [u8; 32] = value
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(Error::new)?;
                Ok(ProtocolVerifyingKey::from_bytes(&bytes)
                    .map_err(Error::new)?)
            }
        }

        impl TryFrom<ThresholdKeyShare> for KeyShare {
            type Error = polysig_protocol::Error;

            fn try_from(
                value: ThresholdKeyShare,
            ) -> std::result::Result<Self, Self::Error> {
                let key_share: driver::KeyShare =
                    (&value).try_into()?;
                Ok(key_share.into())
            }
        }

        impl TryFrom<KeyShare> for ThresholdKeyShare {
            type Error = polysig_protocol::Error;

            fn try_from(
                value: KeyShare,
            ) -> std::result::Result<Self, Self::Error> {
                let key_share: driver::KeyShare = value.into();
                Ok((&key_share).try_into()?)
            }
        }

        #[doc(hidden)]
        #[napi(object)]
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        pub struct Signature {
            pub signature_bytes: Vec<u8>,
        }

        impl TryFrom<Signature> for frost::Signature {
            type Error = napi::Error;

            fn try_from(
                value: Signature,
            ) -> std::result::Result<Self, Self::Error> {
                let signature = frost::Signature::deserialize(
                    &value.signature_bytes,
                )
                .map_err(Error::new)?;
                Ok(signature)
            }
        }

        impl TryFrom<frost::Signature> for Signature {
            type Error = napi::Error;

            fn try_from(
                value: frost::Signature,
            ) -> std::result::Result<Self, Self::Error> {
                let signature_bytes =
                    value.serialize().map_err(Error::new)?;
                Ok(Self { signature_bytes })
            }
        }

        #[doc(hidden)]
        #[napi(object)]
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        pub struct Identifier {
            pub id: u16,
        }

        impl TryFrom<Identifier> for frost::Identifier {
            type Error = napi::Error;

            fn try_from(
                value: Identifier,
            ) -> std::result::Result<Self, Self::Error> {
                Ok(value.id.try_into().map_err(Error::new)?)
            }
        }

        #[doc(hidden)]
        #[napi(object)]
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct PartyOptions {
            pub public_key: Vec<u8>,
            pub participants: Vec<Vec<u8>>,
            pub is_initiator: bool,
            pub verifiers: Vec<VerifyingKey>,
        }

        impl TryFrom<PartyOptions> for frost::PartyOptions {
            type Error = napi::Error;

            fn try_from(
                value: PartyOptions,
            ) -> std::result::Result<Self, Self::Error> {
                let mut verifiers =
                    Vec::with_capacity(value.verifiers.len());
                for verifier in value.verifiers {
                    verifiers.push(verifier.try_into()?);
                }
                Ok(polysig_driver::PartyOptions::new(
                    value.public_key,
                    value.participants,
                    value.is_initiator,
                    verifiers,
                )
                .map_err(Error::new)?)
            }
        }
    };
}

pub(crate) use frost_impl;
pub(crate) use frost_types;
