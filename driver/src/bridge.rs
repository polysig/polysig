use std::num::NonZeroU16;

use futures::StreamExt;
use mpc_client::{Event, EventStream, NetworkTransport, Transport};
use mpc_protocol::{SessionId, SessionState};

use crate::{
    public_key_to_str, Driver, Error, ProtocolDriver, Round,
};

/// Connects a network transport with a protocol driver.
pub(crate) struct Bridge<D: ProtocolDriver> {
    pub(crate) transport: Transport,
    pub(crate) driver: Option<D>,
    pub(crate) session: SessionState,
    pub(crate) party_number: NonZeroU16,
}

impl<D: ProtocolDriver> Bridge<D> {
    /// Handle event from the client event loop stream.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<D::Output>, D::Error> {
        if let Event::JsonMessage {
            message,
            session_id,
            ..
        } = event
        {
            if let Some(session_id) = &session_id {
                if session_id != &self.session.session_id {
                    return Err(
                        Box::new(Error::SessionIdMismatch).into()
                    );
                }
            } else {
                return Err(Box::new(Error::SessionIdRequired).into());
            }

            let message: D::Message = message.deserialize()?;

            let driver = self.driver.as_mut().unwrap();
            let round_info = driver.round_info()?;

            /*
            let current_round: NonZeroU16 =
                (round_info.round_number as u16).try_into().unwrap();

            if message.round_number() != current_round {
                panic!(
                    "out of order message message_round = {}, current_round = {}",
                    message.round_number(),
                    current_round,
                );
            }
            */

            /*
            println!(
                "Message round: {}, session round: {} {} {}",
                message.round_number(),
                round_info.round_number,
                round_info.is_echo,
                round_info.can_finalize,
            );
            */

            if !round_info.can_finalize {
                driver.handle_incoming(message)?;
                let round_info = driver.round_info()?;
                if round_info.can_finalize {
                    if let Some(result) =
                        driver.try_finalize_round()?
                    {
                        return Ok(Some(result));
                    }

                    let messages = driver.proceed()?;

                    println!(
                        "*** DISPATCH MESSAGES ({}) ***",
                        messages.len()
                    );

                    self.dispatch_round_messages(messages).await?;
                }
            }
        }

        Ok(None)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<(), D::Error> {
        let driver = self.driver.as_mut().unwrap();
        let messages = driver.proceed()?;
        self.dispatch_round_messages(messages).await?;
        Ok(())
    }

    /// Send messages to peers.
    async fn dispatch_round_messages(
        &mut self,
        messages: Vec<D::Message>,
    ) -> Result<(), D::Error> {
        for message in messages {
            let party_number = message.receiver();

            let owner_key =
                self.session.peer_key(self.party_number).unwrap();
            let peer_key =
                self.session.peer_key(*party_number).unwrap();

            tracing::info!(
                to = public_key_to_str(peer_key),
                from = public_key_to_str(owner_key),
                "dispatch_message"
            );

            self.transport
                .send_json(
                    peer_key,
                    &message,
                    Some(self.session.session_id),
                )
                .await?;
        }
        Ok(())
    }
}

/// Wait for a driver to complete.
pub async fn wait_for_driver<D>(
    stream: &mut EventStream,
    mut driver: D,
) -> Result<(Transport, D::Output), D::Error>
where
    D: Driver + Into<Transport>,
{
    driver.execute().await?;

    #[allow(unused_assignments)]
    let mut output: Option<D::Output> = None;
    while let Some(event) = stream.next().await {
        let event = event?;
        if let Some(result) = driver.handle_event(event).await? {
            output = Some(result);
            break;
        }
    }
    Ok((driver.into(), output.take().unwrap()))
}

/// Wait for a close event.
///
/// Calling close() on a transport internally sends
/// the message view the event loop so we still need
/// to drive the event loop after calling close.
pub async fn wait_for_close(
    stream: &mut EventStream,
) -> crate::Result<()> {
    while let Some(event) = stream.next().await {
        let event = event?;
        if let Event::Close = event {
            break;
        }
    }
    Ok(())
}

/// Wait for a session finish event.
pub async fn wait_for_session_finish(
    stream: &mut EventStream,
    session_id: SessionId,
) -> crate::Result<()> {
    while let Some(event) = stream.next().await {
        let event = event?;
        if let Event::SessionFinished(id) = event {
            if session_id == id {
                break;
            }
        }
    }
    Ok(())
}
