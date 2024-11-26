use anyhow::Result;
use polysig_driver::signers::eddsa::EddsaSigner;
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct EddsaTestVector {
    /// Secret key..
    #[serde(with = "hex::serde")]
    secret_key: Vec<u8>,
    /// Public key.
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
    /// Message to sign.
    #[serde(with = "hex::serde")]
    message: Vec<u8>,
    /// Signature.
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

/// Test vectors are from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
const TEST_VECTORS: &[u8] =
    include_bytes!("./test_vectors/eddsa.json");

#[test]
fn eddsa_sign() -> Result<()> {
    let vectors: Vec<EddsaTestVector> =
        serde_json::from_slice(TEST_VECTORS)?;

    for test in vectors {
        let private_key: [u8; 32] =
            test.secret_key.as_slice().try_into()?;
        let signing_key = EddsaSigner::from_bytes(&private_key);
        let signer = EddsaSigner::new(Cow::Owned(signing_key));
        assert_eq!(
            test.public_key,
            signer.verifying_key().to_bytes()
        );

        let signature = signer.sign(&test.message);
        assert!(signer.verify(&test.message, &signature).is_ok());
        assert_eq!(test.signature, signature.to_bytes());
    }

    Ok(())
}
