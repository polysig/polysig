//! Generic signature generation for FROST.
use async_trait::async_trait;
use polysig_driver::ProtocolDriver;

use crate::{
    protocols::{Bridge, Driver},
    Result, Transport,
};
use polysig_protocol::{Event, PartyNumber, SessionState};

/// FROST signing driver.
pub struct SignatureDriver<D, O>
where
    D: ProtocolDriver,
{
    bridge: Bridge<D>,
    marker: std::marker::PhantomData<O>,
}

impl<D, O> SignatureDriver<D, O>
where
    D: ProtocolDriver,
{
    /// Create a new FROST signature driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        party_number: PartyNumber,
        driver: D,
    ) -> Self {
        let bridge = Bridge {
            transport,
            driver: Some(driver),
            session,
            party_number,
        };
        Self {
            bridge,
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<D, O> Driver for SignatureDriver<D, O>
where
    D: ProtocolDriver<Output = O> + Send + Sync,
    O: Send + Sync,
{
    type Output = O;

    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>> {
        Ok(self.bridge.handle_event(event).await?)
    }

    async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await?)
    }

    fn into_transport(self) -> Transport {
        self.bridge.transport
    }
}

impl<D, O> From<SignatureDriver<D, O>> for Transport
where
    D: ProtocolDriver,
{
    fn from(value: SignatureDriver<D, O>) -> Self {
        value.bridge.transport
    }
}

macro_rules! frost_sign_impl {
    () => {
        /// Sign a message using the FROST protocol.
        pub async fn sign(
            options: SessionOptions,
            participant: Participant,
            // Identifiers must match the KeyPackage identifiers!
            identifiers: Vec<Identifier>,
            key_share: KeyShare,
            message: Vec<u8>,
        ) -> crate::Result<Signature> {
            let min_signers = options.parameters.threshold as u16;

            // Create the client
            let (client, event_loop) = new_client(options).await?;

            let mut transport: Transport = client.into();

            // Handshake with the server
            transport.connect().await?;

            // Start the event stream
            let mut stream = event_loop.run();

            // Wait for the session to become active
            let client_session = if participant.party().is_initiator()
            {
                let mut other_participants =
                    participant.party().participants().to_vec();
                other_participants.retain(|p| {
                    p != participant.party().public_key()
                });
                SessionHandler::Initiator(SessionInitiator::new(
                    transport,
                    other_participants,
                ))
            } else {
                SessionHandler::Participant(SessionParticipant::new(
                    transport,
                ))
            };

            let (transport, session) =
                wait_for_session(&mut stream, client_session).await?;

            let protocol_session_id = session.session_id;

            // Wait for message to be signed
            let driver = sign::new_driver(
                transport,
                session,
                identifiers,
                min_signers,
                key_share,
                message,
            )?;

            let (mut transport, signature) =
                wait_for_driver(&mut stream, driver).await?;

            // Close the session and socket
            if participant.party().is_initiator() {
                transport.close_session(protocol_session_id).await?;
                wait_for_session_finish(
                    &mut stream,
                    protocol_session_id,
                )
                .await?;
            }
            transport.close().await?;
            wait_for_close(&mut stream).await?;

            Ok(signature)
        }
    };
}

pub(crate) use frost_sign_impl;
