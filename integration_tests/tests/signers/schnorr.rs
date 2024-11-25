use anyhow::Result;
use polysig_driver::signers::schnorr::{SchnorrSigner, VerifyingKey};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Debug, Deserialize)]
struct SchnorrTestVector {
    index: u16,
    #[serde(with = "hex::serde")]
    secret_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    aux_rand: Vec<u8>,
    #[serde(with = "hex::serde")]
    message: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
    verification_result: String,
    #[allow(dead_code)]
    comment: Option<String>,
}

impl SchnorrTestVector {
    pub fn should_verify(&self) -> bool {
        &self.verification_result == "TRUE"
    }
}

/// Test vectors are from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
const TEST_VECTORS: &[u8] =
    include_bytes!("./test_vectors/schnorr-bip340.csv");

#[test]
fn schnorr_sign() -> Result<()> {
    let mut rdr = csv::Reader::from_reader(TEST_VECTORS);
    let mut all_tests = Vec::new();
    let mut completed: Vec<u16> = Vec::new();
    for result in rdr.deserialize() {
        let test: SchnorrTestVector = result?;
        all_tests.push(test.index);

        // Sign and verify
        if !test.secret_key.is_empty() {
            let signing_key =
                SchnorrSigner::from_slice(&test.secret_key)?;
            let signer =
                SchnorrSigner::new(Cow::Borrowed(&signing_key));

            if !test.aux_rand.is_empty() {
                let aux_rand: [u8; 32] =
                    test.aux_rand.as_slice().try_into()?;

                let signature =
                    signer.sign_raw(&test.message, &aux_rand)?;
                let verified = signer
                    .verify_raw(&test.message, &signature)
                    .is_ok();

                assert_eq!(test.should_verify(), verified);
                completed.push(test.index);
            }
        // Verify only (no secret key in test vector)
        } else {
            // let signature_bytes: [u8; 64] =
            //     test.signature.as_slice().try_into()?;

            // Some verification failures are caught
            // parsing either the public key or the signature
            if let (Ok(signature), Ok(verifying_key)) = (
                test.signature.as_slice().try_into(),
                VerifyingKey::from_bytes(&test.public_key),
            ) {
                let verified = verifying_key
                    .verify_raw(&test.message, &signature)
                    .is_ok();
                assert_eq!(test.should_verify(), verified);
            }
            completed.push(test.index);
        }
    }
    assert_eq!(all_tests, completed);
    Ok(())
}
