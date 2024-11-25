//! Driver for the CGGMP protocol.
use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, Error, EventStream, NetworkTransport,
    SessionHandler, SessionInitiator, SessionOptions,
    SessionParticipant, Transport,
};
use futures::StreamExt;
use polysig_driver::{
    cggmp::Participant,
    recoverable_signature::RecoverableSignature,
    synedrion::{
        self,
        ecdsa::{SigningKey, VerifyingKey},
        KeyResharingInputs, NewHolder, OldHolder, PrehashedMessage,
        SchemeParams, SessionId, ThresholdKeyShare,
    },
};
use polysig_protocol::{
    Event, SessionId as ProtocolSessionId, SessionState,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod aux_gen;
mod key_gen;
mod key_init;
mod key_refresh;
mod key_resharing;
mod sign;

#[doc(hidden)]
pub use aux_gen::AuxGenDriver;
#[doc(hidden)]
pub use key_gen::KeyGenDriver;
#[doc(hidden)]
pub use key_init::KeyInitDriver;
#[doc(hidden)]
pub use key_refresh::KeyRefreshDriver;
#[doc(hidden)]
pub use key_resharing::KeyResharingDriver;
#[doc(hidden)]
pub use sign::SignatureDriver;

/// Message sent by key init participants to
/// notify clients that are not participating
/// that their key init phase is completed.
#[derive(Serialize, Deserialize)]
pub(crate) struct KeyInitAck {
    /// Index of the party.
    pub party_index: usize,
    /// Verifying key from the generated threshold key share.
    pub key_share_verifying_key: VerifyingKey,
}

/// Result type for the CGGMP protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// Run threshold DKG for the CGGMP protocol.
pub async fn dkg<P: SchemeParams + 'static>(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
) -> crate::Result<ThresholdKeyShare<P, VerifyingKey>> {
    let n = options.parameters.parties as usize;
    let t = options.parameters.threshold as usize;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if participant.party().is_initiator() {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participant.party().participants().to_vec(),
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    let (transport, stream, t_key_share, acks) = make_dkg_init::<P>(
        t,
        &participant,
        transport,
        stream,
        protocol_session_id,
        session.clone(),
        session_id,
    )
    .await?;

    // Do key resharing phase
    let (mut transport, mut stream, t_key_share) = if t < n {
        let account_verifying_key =
            if let Some(t_key_share) = &t_key_share {
                t_key_share.verifying_key().clone()
            } else {
                let ack = acks
                    .iter()
                    .find(|a| a.party_index == 0)
                    .ok_or(Error::NoKeyInitAck)?;
                ack.key_share_verifying_key.clone()
            };

        make_dkg_reshare::<P>(
            t,
            t,
            account_verifying_key,
            t_key_share,
            transport,
            stream,
            session,
            session_id,
            participant.signing_key().to_owned(),
            participant.party().verifiers(),
        )
        .await?
    } else {
        (transport, stream, t_key_share.unwrap())
    };

    // Close the session and socket
    if participant.party().is_initiator() {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(t_key_share)
}

/// Make initialize key share for threshold DKG.
async fn make_dkg_init<P: SchemeParams + 'static>(
    t: usize,
    participant: &Participant,
    transport: Transport,
    mut stream: EventStream,
    protocol_session_id: ProtocolSessionId,
    session: SessionState,
    session_id: SessionId,
) -> crate::Result<(
    Transport,
    EventStream,
    Option<ThresholdKeyShare<P, VerifyingKey>>,
    Vec<KeyInitAck>,
)> {
    let init_verifiers = participant
        .party()
        .verifiers()
        .iter()
        .take(t)
        .cloned()
        .collect::<Vec<_>>();
    let party_index = participant.party().party_index();

    if party_index < t {
        // Wait for key init generation
        let key_init = KeyInitDriver::<P>::new(
            transport,
            session,
            session_id,
            participant.signing_key().to_owned(),
            init_verifiers,
        )?;

        let (mut transport, key_share) =
            wait_for_driver(&mut stream, key_init).await?;

        let ack = KeyInitAck {
            party_index,
            key_share_verifying_key: key_share
                .verifying_key()
                .unwrap()
                .clone(),
        };

        // Notify participants not involved in key init
        // that we are done
        // let other_participants = &participants[t..];
        let other_participants = participant
            .party()
            .participants()
            .iter()
            .filter(|p| {
                p.as_slice() != participant.party().public_key()
            })
            .collect::<Vec<_>>();
        for other_public_key in other_participants {
            transport
                .send_json(
                    other_public_key,
                    &ack,
                    Some(protocol_session_id),
                )
                .await?;
        }

        let mut acks = vec![ack];
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::JsonMessage {
                message,
                session_id,
                ..
            } = event
            {
                if session_id.as_ref() == Some(&protocol_session_id) {
                    if let Ok(ack) =
                        message.deserialize::<KeyInitAck>()
                    {
                        acks.push(ack);
                        if acks.len() == t {
                            break;
                        }
                    }
                }
            }
        }

        let t_key_share =
            ThresholdKeyShare::from_key_share(&key_share);
        Ok((transport, stream, Some(t_key_share), acks))
    } else {
        // If we are not participating in key init then wait
        // so we know when to proceed to the key resharing phase
        let mut acks = Vec::new();
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::JsonMessage {
                message,
                session_id,
                ..
            } = event
            {
                if session_id.as_ref() == Some(&protocol_session_id) {
                    if let Ok(ack) =
                        message.deserialize::<KeyInitAck>()
                    {
                        acks.push(ack);
                        if acks.len() == t {
                            break;
                        }
                    }
                }
            }
        }
        Ok((transport, stream, None, acks))
    }
}

/// Reshare key shares.
pub async fn reshare<P: SchemeParams>(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
    account_verifying_key: VerifyingKey,
    key_share: Option<ThresholdKeyShare<P, VerifyingKey>>,
    old_threshold: usize,
    new_threshold: usize,
) -> crate::Result<ThresholdKeyShare<P, VerifyingKey>> {
    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if participant.party().is_initiator() {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participant.party().participants().to_vec(),
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    let (mut transport, mut stream, new_key_share) =
        make_dkg_reshare::<P>(
            old_threshold,
            new_threshold,
            account_verifying_key,
            key_share,
            transport,
            stream,
            session,
            session_id,
            participant.signing_key().to_owned(),
            participant.party().verifiers(),
        )
        .await?;

    // Close the session and socket
    if participant.party().is_initiator() {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(new_key_share)
}

/// Drive the key resharing phase of threshold DKG.
async fn make_dkg_reshare<P: SchemeParams + 'static>(
    old_threshold: usize,
    new_threshold: usize,
    account_verifying_key: VerifyingKey,
    t_key_share: Option<ThresholdKeyShare<P, VerifyingKey>>,
    transport: Transport,
    mut stream: EventStream,
    session: SessionState,
    session_id: SessionId,
    signer: SigningKey,
    verifiers: &[VerifyingKey],
) -> Result<(
    Transport,
    EventStream,
    ThresholdKeyShare<P, VerifyingKey>,
)> {
    let old_holders = BTreeSet::from_iter(
        verifiers.iter().cloned().take(old_threshold),
    );

    let inputs = if let Some(t_key_share) = t_key_share {
        let new_holder = NewHolder {
            verifying_key: account_verifying_key,
            old_threshold,
            old_holders,
        };

        KeyResharingInputs {
            old_holder: Some(OldHolder {
                key_share: t_key_share.clone(),
            }),
            new_holder: Some(new_holder.clone()),
            new_holders: verifiers
                .to_vec()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            new_threshold,
        }
    } else {
        let new_holder = NewHolder {
            verifying_key: account_verifying_key.clone(),
            old_threshold,
            old_holders,
        };

        KeyResharingInputs {
            old_holder: None,
            new_holder: Some(new_holder.clone()),
            new_holders: verifiers
                .to_vec()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            new_threshold,
        }
    };

    let driver = KeyResharingDriver::<P>::new(
        transport,
        session,
        session_id,
        signer,
        verifiers.to_vec(),
        inputs,
    )?;

    let (transport, key_share) =
        wait_for_driver(&mut stream, driver).await?;

    Ok((transport, stream, key_share))
}

/// Sign a message using the CGGMP protocol.
pub async fn sign<P: SchemeParams + 'static>(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
    key_share: &synedrion::KeyShare<P, VerifyingKey>,
    prehashed_message: &PrehashedMessage,
) -> crate::Result<RecoverableSignature> {
    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if participant.party().is_initiator() {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participant.party().participants().to_vec(),
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    // Wait for aux gen protocol to complete
    let driver = AuxGenDriver::<P>::new(
        transport,
        session.clone(),
        session_id,
        participant.signing_key().clone(),
        participant.party().verifiers().to_vec(),
    )?;
    let (transport, aux_info) =
        wait_for_driver(&mut stream, driver).await?;

    // Wait for message to be signed
    let driver = SignatureDriver::<P>::new(
        transport,
        session,
        session_id,
        participant.signing_key().clone(),
        participant.party().verifiers().to_vec(),
        key_share,
        &aux_info,
        prehashed_message,
    )?;
    let (mut transport, signature) =
        wait_for_driver(&mut stream, driver).await?;

    // Close the session and socket
    if participant.party().is_initiator() {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }
    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(signature)
}
