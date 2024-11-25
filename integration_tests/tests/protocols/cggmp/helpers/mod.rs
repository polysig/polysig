use crate::test_utils::new_client;
use anyhow::Result;
use futures::{Stream, StreamExt};
use polysig_client::{
    Driver, NetworkTransport, SessionEventHandler, SessionHandler,
    SessionInitiator, SessionParticipant, Transport,
};
use polysig_driver::{
    k256::ecdsa::{SigningKey, VerifyingKey},
    synedrion::PrehashedMessage,
};
use polysig_protocol::{Event, Keypair, SessionState};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use std::pin::Pin;

mod derived_keys;
mod dkg_sign;
mod drivers;
mod reshare;

pub use derived_keys::*;
pub use dkg_sign::*;
pub use drivers::*;
pub use reshare::*;

pub fn make_signing_message() -> Result<PrehashedMessage> {
    let message = "this is the message that is sent out";
    let prehashed_message: PrehashedMessage =
        Keccak256::digest(message.as_bytes())
            .as_slice()
            .try_into()?;
    Ok(prehashed_message)
}

pub fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| *signer.verifying_key())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

type SessionStream = Pin<
    Box<dyn Stream<Item = Result<Event, polysig_client::Error>> + Send>,
>;

/// Drive streams to prepare sessions.
pub async fn drive_stream_sessions(
    streams: Vec<SessionStream>,
    sessions: Vec<SessionHandler>,
) -> Result<Vec<(Transport, SessionState, SessionStream)>> {
    let mut jhs = Vec::new();
    for (mut stream, mut session) in streams.into_iter().zip(sessions)
    {
        let jh = tokio::task::spawn(async move {
            let mut state: Option<(
                Transport,
                SessionState,
                SessionStream,
            )> = None;
            while let Some(event) = stream.next().await {
                let event = event?;
                if let Some(session_state) =
                    session.handle_event(event).await?
                {
                    let transport = session.into_transport();
                    state = Some((transport, session_state, stream));
                    break;
                }
            }

            Ok::<_, anyhow::Error>(state)
        });

        jhs.push(jh);
    }

    let results = futures::future::try_join_all(jhs).await.unwrap();
    let mut states = Vec::new();
    for result in results {
        let result = result?;
        states.push(result.unwrap());
    }

    Ok(states)
}

/// Create clients and prepare the sessions.
pub async fn make_client_sessions(
    server: &str,
    server_public_key: &[u8],
    n: usize,
) -> Result<Vec<(Transport, SessionState, SessionStream)>> {
    // Create the clients
    let mut clients = Vec::new();
    let mut event_loops = Vec::new();
    let mut keypairs: Vec<Keypair> = Vec::new();
    for _ in 0..n {
        let (client, event_loop, keypair) =
            new_client::<anyhow::Error>(
                server,
                server_public_key.to_vec(),
            )
            .await?;

        clients.push(client);
        event_loops.push(event_loop);
        keypairs.push(keypair);
    }

    // Each client handshakes with the server
    let mut transports = Vec::new();
    for client in clients {
        let mut transport: Transport = client.into();
        transport.connect().await?;
        transports.push(transport);
    }

    // Event loop streams
    let mut streams = Vec::new();
    for event_loop in event_loops {
        streams.push(event_loop.run());
    }

    // Public keys of the participants
    let session_participants = keypairs
        .iter()
        .skip(1)
        .map(|k| k.public_key().to_vec())
        .collect::<Vec<_>>();

    // First handler is the initiator
    let mut handlers =
        vec![SessionHandler::Initiator(SessionInitiator::new(
            transports.remove(0),
            session_participants,
        ))];

    // Remaining transports become participants
    for transport in transports {
        handlers.push(SessionHandler::Participant(
            SessionParticipant::new(transport),
        ));
    }

    drive_stream_sessions(streams, handlers).await
}

/// Execute a collection of drivers.
pub async fn execute_drivers<D>(
    streams: Vec<SessionStream>,
    mut drivers: Vec<D>,
) -> Result<Vec<(D::Output, Transport, SessionStream)>>
where
    D: Driver + Send + 'static,
    D::Output: Send,
{
    // Execute the driver protocols
    for driver in &mut drivers {
        driver.execute().await.unwrap();
    }

    let mut jhs = Vec::new();
    for (mut stream, mut driver) in streams.into_iter().zip(drivers) {
        let jh = tokio::task::spawn(async move {
            let mut output: Option<(D::Output, D, SessionStream)> =
                None;
            while let Some(event) = stream.next().await {
                let event = event?;

                if let Some(result) =
                    driver.handle_event(event).await.unwrap()
                {
                    output = Some((result, driver, stream));
                    break;
                }
            }

            Ok::<_, anyhow::Error>(output)
        });

        jhs.push(jh);
    }

    let results = futures::future::try_join_all(jhs).await.unwrap();
    let mut output = Vec::new();
    for result in results {
        let result = result?;
        let (result, driver, stream) = result.unwrap();
        output.push((result, driver.into_transport(), stream));
    }

    Ok(output)
}
