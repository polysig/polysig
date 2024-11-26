//! Macros for the FROST protocol.
pub(crate) mod dkg;
pub(crate) mod sign;

macro_rules! key_share_pem {
    () => {
        impl TryFrom<&KeyShare> for crate::KeyShare {
            type Error = polysig_protocol::Error;

            fn try_from(
                value: &KeyShare,
            ) -> std::result::Result<Self, Self::Error> {
                let key_share = serde_json::to_vec(value)?;
                let key_share = pem::Pem::new(TAG, key_share);
                let key_share = pem::encode(&key_share);
                Ok(Self {
                    version: PEM_VERSION,
                    contents: key_share,
                })
            }
        }

        impl TryFrom<&crate::KeyShare> for KeyShare {
            type Error = polysig_protocol::Error;

            fn try_from(
                value: &crate::KeyShare,
            ) -> std::result::Result<Self, Self::Error> {
                let key_share = pem::parse(&value.contents)?;
                if key_share.tag() != TAG {
                    return Err(polysig_protocol::Error::PemTag(
                        TAG.to_string(),
                        key_share.tag().to_string(),
                    ));
                }
                let key_share: KeyShare =
                    serde_json::from_slice(key_share.contents())?;
                Ok(key_share)
            }
        }
    };
}

pub(crate) use key_share_pem;
