use anyhow::Result;

use crate::test_utils::{
    server_public_key, session_handshake, spawn_server,
};

/// Uses the session helpers from the driver library to determine
/// when both participants in a session are active.
#[tokio::test]
async fn integration_session_handshake() -> Result<()> {
    //crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    let expected_participants = 2;
    let connected_participants =
        session_handshake::run(&server, server_public_key).await?;
    assert_eq!(expected_participants, connected_participants);

    Ok(())
}
