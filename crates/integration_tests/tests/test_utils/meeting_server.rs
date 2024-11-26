use anyhow::Result;
use axum_server::Handle;

use std::{net::SocketAddr, thread};
use tokio::sync::oneshot;

use polysig_meeting_server::{MeetingServer, ServerConfig};

const ADDR: &str = "127.0.0.1:0";

struct MockMeetingServer {
    handle: Handle,
}

impl MockMeetingServer {
    fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new(),
        })
    }

    async fn start(&self) -> Result<()> {
        let addr: SocketAddr = ADDR.parse::<SocketAddr>()?;
        tracing::info!("start mock meeting server {:#?}", addr);
        let config =
            ServerConfig::load("tests/meeting-config.toml").await?;
        let server = MeetingServer::new(config);
        server.start(addr, self.handle.clone()).await?;
        Ok(())
    }

    /// Run the mock server in a separate thread.
    fn spawn(
        tx: oneshot::Sender<SocketAddr>,
    ) -> Result<ShutdownHandle> {
        let server = MockMeetingServer::new()?;
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
                    .expect("failed to start meeting server");
            });
        });

        Ok(ShutdownHandle(user_handle))
    }
}

/// Ensure the server is shutdown when the handle is dropped.
pub struct ShutdownHandle(Handle);

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        tracing::info!("shutdown mock meeting server");
        self.0.shutdown();
    }
}

pub fn spawn_meeting_server(
) -> Result<(oneshot::Receiver<SocketAddr>, ShutdownHandle)> {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockMeetingServer::spawn(tx)?;
    Ok((rx, handle))
}
