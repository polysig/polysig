use anyhow::Result;
use futures::StreamExt;
use polysig_client::NetworkTransport;
use polysig_protocol::Event;

use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    // Create new clients
    let (mut initiator, event_loop_i, _initiator_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (mut participant, _event_loop_p, participant_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let session_participants =
        vec![participant_key.public_key().to_vec()];

    initiator.connect().await?;
    participant.connect().await?;

    let mut s = event_loop_i.run();
    while let Some(event) = s.next().await {
        let event = event?;
        if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
            log::trace!("initiator {:#?}", event);
        } else {
            tracing::trace!("initiator {:#?}", event);
        }
        match &event {
            Event::ServerConnected { .. } => {
                initiator
                    .new_session(session_participants.clone())
                    .await?;
            }
            Event::SessionTimeout(_) => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
