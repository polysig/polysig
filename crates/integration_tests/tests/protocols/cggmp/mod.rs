use crate::test_utils::{server_public_key, spawn_server};
use anyhow::Result;

mod helpers;

/// CGGMP distributed key generation.
#[tokio::test]
async fn cggmp_driver_keygen() -> Result<()> {
    // crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_keygen(&server, server_public_key).await?;

    Ok(())
}

/// CGGMP auxiliary info.
#[tokio::test]
async fn cggmp_driver_aux_info() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_aux_info(&server, server_public_key).await?;

    Ok(())
}

/// CGGMP threshold sign.
///
/// This test re-uses the AuxInfo created during DKG for the signing
/// but in the real-world signing would need to generate fresh AuxInfo
/// which is done in the keygen_sign test spec.
#[tokio::test]
async fn cggmp_driver_threshold_sign() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_threshold_sign(&server, server_public_key).await?;

    Ok(())
}

/// CGGMP DKG followed by signing (2-of-3).
#[tokio::test]
async fn cggmp_dkg_sign_2_3() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_dkg_sign_2_3(&server, server_public_key).await?;

    Ok(())
}

/// CGGMP DKG followed by signing (2-of-2).
///
/// Note that this follows a different code path to the 2-of-3
/// which also runs a resharing phase.
#[tokio::test]
async fn cggmp_dkg_sign_2_2() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_dkg_sign_2_2(&server, server_public_key).await?;

    Ok(())
}

/// CGGMP DKG followed by resharing and signing.
#[tokio::test]
async fn cggmp_dkg_reshare_2_2_to_3_4() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_dkg_reshare_2_2_to_3_4(&server, server_public_key)
        .await?;

    Ok(())
}

/// CGGMP DKG followed by signing (2-of-2) using
/// derived child keys (BIP32).
#[tokio::test]
async fn cggmp_dkg_derived_2_2() -> Result<()> {
    // crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    helpers::run_dkg_derived_2_2(&server, server_public_key).await?;

    Ok(())
}
