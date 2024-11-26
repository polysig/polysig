use super::super::{
    execute_drivers, make_client_sessions, make_signers,
};
use anyhow::Result;
use polysig_client::{
    cggmp::KeyGenDriver, wait_for_close, NetworkTransport,
};
use polysig_driver::synedrion::{SessionId, TestParams};
use rand::{rngs::OsRng, Rng};

pub async fn run_keygen(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 5;
    let rng = &mut OsRng;
    let session_id: [u8; 32] = rng.gen();
    let session_id = SessionId::from_seed(&session_id);

    let (mut signers, verifiers) = make_signers(n);
    let results =
        make_client_sessions(server, &server_public_key, n).await?;

    // Prepare for key generation
    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    for result in results {
        let (transport, session, stream) = result;
        streams.push(stream);
        drivers.push(KeyGenDriver::<TestParams>::new(
            transport,
            session,
            session_id,
            signers.remove(0),
            verifiers.clone(),
        )?);
    }

    let results = execute_drivers(streams, drivers).await?;

    let mut key_shares = Vec::new();
    let mut transports = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        key_shares.push(output);
        transports.push((transport, stream));
    }
    assert_eq!(n, key_shares.len());

    // Close the client sockets
    for (transport, mut stream) in transports {
        transport.close().await?;
        wait_for_close(&mut stream).await?;
    }

    Ok(())
}