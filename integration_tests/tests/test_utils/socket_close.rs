use anyhow::Result;
use futures::StreamExt;
use polysig_client::NetworkTransport;
use polysig_protocol::Event;

use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let (mut initiator, event_loop_i, _) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    initiator.connect().await?;

    let mut s = event_loop_i.run();
    while let Some(event) = s.next().await {
        let event = event?;
        match &event {
            Event::ServerConnected { .. } => {
                initiator.close().await?;
            }
            Event::Close => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}
