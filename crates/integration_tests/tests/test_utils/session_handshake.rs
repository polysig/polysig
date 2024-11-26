use anyhow::Result;
use futures::StreamExt;

use polysig_client::{
    NetworkTransport, SessionEventHandler, SessionInitiator,
    SessionParticipant, Transport,
};
use polysig_protocol::SessionState;

use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<usize> {
    let mut completed: Vec<SessionState> = Vec::new();

    // Create new clients
    let (client_i, event_loop_i, _) = new_client::<anyhow::Error>(
        server,
        server_public_key.clone(),
    )
    .await?;
    let (client_p, event_loop_p, participant_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_transport: Transport = client_p.into();

    let session_participants =
        vec![participant_key.public_key().to_vec()];

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_transport.connect().await?;

    let mut client_i_session = SessionInitiator::new(
        client_i_transport,
        session_participants,
    );
    let mut client_p_session =
        SessionParticipant::new(client_p_transport);

    let mut s_i = event_loop_i.run();
    let mut s_p = event_loop_p.run();

    loop {
        if completed.len() == 2 {
            break;
        }

        tokio::select! {
            event = s_i.next() => {
                match event {
                    Some(event) => {
                        let event = event?;

                        if let Some(session) =
                            client_i_session.handle_event(event).await? {
                            completed.push(session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p.next() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_p_session.handle_event(event).await? {
                            completed.push(session);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(completed.len())
}
