use anyhow::Result;
use polysig_driver::{
    recoverable_signature::RecoverableSignature,
    signers::ecdsa::EcdsaSigner,
};
use serde::Deserialize;
use std::borrow::Cow;

/// Test vectors are generated using `ethers`,
/// see scripts/ecdsa-test-vectors.
const TEST_VECTORS: &str = r#"
{
  "signedMessage": {
    "privateKey": "f64abc91d673bcf100c3cf2bc42507df566d36a18189ae41c377c55ee26a44fd",
    "message": "example message",
    "signature": {
      "r": "e75ae7a14cc57c75f1fcf7343c06f9e31419ccd06b25a788a0d596119bc187f2",
      "s": "75a1de718def771b819d352ffb3f2a95b41da3ecdcbc592b07f956c7828d210f",
      "v": 28
    }
  }
}
"#;

#[derive(Deserialize)]
struct EthereumSignature {
    #[serde(with = "hex::serde")]
    pub r: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub s: Vec<u8>,
    pub v: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestSignedMessage {
    #[serde(with = "hex::serde")]
    private_key: Vec<u8>,
    message: String,
    signature: EthereumSignature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVectors {
    signed_message: TestSignedMessage,
}

#[test]
fn ecdsa_sign_message() -> Result<()> {
    let vectors: TestVectors = serde_json::from_str(TEST_VECTORS)?;
    let spec = vectors.signed_message;

    let signing_key =
        EcdsaSigner::from_slice(spec.private_key.as_slice())?;
    let signer = EcdsaSigner::new(Cow::Owned(signing_key));

    let (signature, recid) = signer.sign_eth_message(spec.message)?;
    let (r, s) = signature.split_bytes();

    assert_eq!(&spec.signature.r, r.as_slice());
    assert_eq!(&spec.signature.s, s.as_slice());
    assert_eq!(spec.signature.v - 27, u8::from(recid));

    /*
    println!("r: {:#?}", hex::encode(r));
    println!("s: {:#?}", hex::encode(s));
    println!("v: {:#?}", recid);
    */

    Ok(())
}

#[test]
fn ecdsa_sign_verify_recover() -> Result<()> {
    use sha3::{Digest, Keccak256};

    let signing_key = EcdsaSigner::random();
    let signer = EcdsaSigner::new(Cow::Owned(signing_key));
    let verifying_key = signer.verifying_key();
    let message = "example message";
    let (signature, recovery_id) =
        signer.sign_eth(message.as_bytes())?;
    let recoverable_signature = RecoverableSignature {
        bytes: signature.to_bytes().to_vec(),
        recovery_id: recovery_id.into(),
    };

    let hash =
        Keccak256::new_with_prefix(message).finalize().to_vec();
    signer.verify_prehash(&hash, &signature)?;

    let public_key = EcdsaSigner::recover(
        message.as_bytes(),
        recoverable_signature,
    )?;
    assert_eq!(verifying_key, &public_key);

    Ok(())
}
