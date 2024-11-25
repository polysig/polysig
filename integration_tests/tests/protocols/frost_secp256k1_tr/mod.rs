use crate::test_utils::{server_public_key, spawn_server};
use anyhow::Result;

use polysig_driver::k256::schnorr::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

mod dkg;
mod sign;

pub fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| signer.verifying_key().clone())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

/// FROST distributed key generation.
#[tokio::test]
async fn frost_secp256k1_tr_dkg_2_3() -> Result<()> {
    // crate::test_utils::init_tracing();
    //

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let t = 2;
    let n = 3;

    let server_public_key = server_public_key().await?;
    let (_, key_shares, _) =
        dkg::run_dkg(t, n, &server, server_public_key).await?;

    assert_eq!(n as usize, key_shares.len());

    Ok(())
}

/// FROST DKG followed by signing (2-of-3).
#[tokio::test]
async fn frost_secp256k1_tr_dkg_sign_2_3() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    sign::run_dkg_sign_2_3(&server, server_public_key).await?;

    Ok(())
}

/// FROST DKG followed by signing (3-of-5).
#[tokio::test]
async fn frost_secp256k1_tr_dkg_sign_3_5() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    sign::run_dkg_sign_3_5(&server, server_public_key).await?;

    Ok(())
}

/// FROST DKG followed by signing (5-of-9).
#[tokio::test]
async fn frost_secp256k1_tr_dkg_sign_5_9() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    sign::run_dkg_sign_5_9(&server, server_public_key).await?;

    Ok(())
}
