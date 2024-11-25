use anyhow::Result;
use futures::StreamExt;
use polysig_client::{Client, EventLoop, NetworkTransport};
use polysig_protocol::Event;
use tokio::sync::mpsc;

use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    // Create new clients
    let (initiator, event_loop_i, initiator_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (participant, event_loop_p, _participant_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let ev_i = initiator_client::<anyhow::Error>(
        initiator,
        event_loop_i,
        shutdown_tx,
    );
    let ev_p = participant_client::<anyhow::Error>(
        participant,
        event_loop_p,
        initiator_key.public_key(),
        shutdown_rx,
    );

    // Must drive the event loop futures
    let (res_i, res_p) = futures::join!(ev_i, ev_p);

    assert!(res_i.is_ok());
    assert!(res_p.is_ok());

    Ok(())
}

pub async fn initiator_client<E>(
    mut client: Client,
    event_loop: EventLoop,
    shutdown_tx: mpsc::Sender<()>,
) -> Result<(), E>
where
    E: From<polysig_client::Error> + From<polysig_protocol::Error>,
{
    client.connect().await?;

    let mut s = event_loop.run();
    while let Some(event) = s.next().await {
        let event = event?;
        if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
            log::trace!("initiator {:#?}", event);
        } else {
            tracing::trace!("initiator {:#?}", event);
        }
        match &event {
            // Once the peer connection is established we can
            // start sending messages over the encrypted channel
            Event::PeerConnected { peer_key } => {
                // Send the ping
                client
                    .send_json(&peer_key, &"ping".to_string(), None)
                    .await?;
            }
            Event::JsonMessage { message, .. } => {
                let message: &str = message.deserialize()?;
                if message == "pong" {
                    // Got a pong so break out of the event loop
                    let _ = shutdown_tx.send(()).await;
                    break;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub async fn participant_client<E>(
    mut client: Client,
    event_loop: EventLoop,
    initiator_public_key: &[u8],
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<(), E>
where
    E: From<polysig_client::Error> + From<polysig_protocol::Error>,
{
    client.connect().await?;

    let mut s = event_loop.run();
    loop {
        tokio::select! {
            biased;
            shutdown = shutdown_rx.recv() => {
                if shutdown.is_some() {
                    break;
                }
            }
            event = s.next() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
                            log::trace!("participant {:#?}", event);
                        } else {
                            tracing::trace!("participant {:#?}", event);
                        }
                        match &event {
                            Event::ServerConnected { .. } => {
                                // Now we can connect to a peer
                                client.connect_peer(initiator_public_key).await?;
                            }
                            // Once the peer connection is established
                            // we can start sending messages over
                            // the encrypted channel
                            Event::JsonMessage { peer_key, message, .. } => {
                                let message: &str = message.deserialize()?;
                                if message == "ping" {
                                    client.send_json(&peer_key, &"pong".to_string(), None).await?;
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
