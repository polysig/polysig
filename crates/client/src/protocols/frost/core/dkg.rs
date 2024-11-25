//! Generic distributed key generation for FROST.
use crate::{
    protocols::{Bridge, Driver},
    Result, Transport,
};
use async_trait::async_trait;
use polysig_protocol::{Event, PartyNumber, SessionState};

use polysig_driver::ProtocolDriver;

/// Generic FROST key generation driver.
pub struct DkgDriver<D, O>
where
    D: ProtocolDriver,
{
    bridge: Bridge<D>,
    marker: std::marker::PhantomData<O>,
}

impl<D, O> DkgDriver<D, O>
where
    D: ProtocolDriver,
{
    /// Create a new FROST key generator.
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
impl<D, O> Driver for DkgDriver<D, O>
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

impl<D, O> From<DkgDriver<D, O>> for Transport
where
    D: ProtocolDriver,
{
    fn from(value: DkgDriver<D, O>) -> Self {
        value.bridge.transport
    }
}

macro_rules! frost_dkg_impl {
    () => {
        /// Run distributed key generation for the FROST protocol.
        pub async fn dkg(
            options: SessionOptions,
            participant: Participant,
        ) -> crate::Result<KeyShare> {
            let params = options.parameters;

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

            let mut identifiers: Vec<Identifier> =
                Vec::with_capacity(params.parties.into());
            for index in 1..=params.parties {
                identifiers
                    .push(index.try_into().map_err(Error::from)?);
            }

            let key_gen = dkg::new_driver(
                transport,
                session,
                params,
                identifiers,
            )?;

            let (transport, key_share) =
                wait_for_driver(&mut stream, key_gen).await?;

            transport.close().await?;
            wait_for_close(&mut stream).await?;

            Ok(key_share)
        }
    };
}

pub(crate) use frost_dkg_impl;
