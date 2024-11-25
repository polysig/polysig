use anyhow::Result;
use axum_server::Handle;

use std::{net::SocketAddr, thread};
use tokio::{fs, sync::oneshot};

use polysig_protocol::Keypair;

use polysig_relay_server::{RelayServer, ServerConfig};

const ADDR: &str = "127.0.0.1:0";

/// Get the public key for the test server.
pub async fn server_public_key() -> Result<Vec<u8>> {
    let contents = fs::read_to_string("tests/test.pem").await?;
    let keypair = Keypair::decode_pem(&contents)?;
    Ok(keypair.public_key().to_vec())
}

struct MockRelayServer {
    handle: Handle,
}

impl MockRelayServer {
    fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new(),
        })
    }

    async fn start(&self) -> Result<()> {
        let addr: SocketAddr = ADDR.parse::<SocketAddr>()?;
        tracing::info!("start mock relay server {:#?}", addr);
        let (config, keypair) =
            ServerConfig::load("tests/config.toml").await?;
        let server = RelayServer::new(config, keypair);
        server.start(addr, self.handle.clone()).await?;
        Ok(())
    }

    /// Run the mock server in a separate thread.
    fn spawn(
        tx: oneshot::Sender<SocketAddr>,
    ) -> Result<ShutdownHandle> {
        let server = MockRelayServer::new()?;
        let listen_handle = server.handle.clone();
        let user_handle = server.handle.clone();

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                loop {
                    if let Some(addr) =
                        listen_handle.listening().await
                    {
                        tracing::info!(
                            "server has started {:#?}",
                            addr
                        );
                        tx.send(addr).expect(
                            "failed to send listening notification",
                        );
                        break;
                    }
                }
            });
        });

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                server
                    .start()
                    .await
                    .expect("failed to start relay server");
            });
        });

        Ok(ShutdownHandle(user_handle))
    }
}

/// Ensure the server is shutdown when the handle is dropped.
pub struct ShutdownHandle(Handle);

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        tracing::info!("shutdown mock relay server");
        self.0.shutdown();
    }
}

pub fn spawn_server(
) -> Result<(oneshot::Receiver<SocketAddr>, ShutdownHandle)> {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockRelayServer::spawn(tx)?;
    Ok((rx, handle))
}
