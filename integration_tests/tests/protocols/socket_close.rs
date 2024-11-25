use crate::test_utils::{
    server_public_key, socket_close, spawn_server,
};
use anyhow::Result;

/// Creates a client that handshakes with the server and
/// then explicitly closes the connection.
#[tokio::test]
async fn integration_socket_close() -> Result<()> {
    //crate::test_utils::init_tracing();
    //

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    socket_close::run(&server, server_public_key).await?;

    Ok(())
}
