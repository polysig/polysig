use anyhow::Result;
use polysig_driver::{
    cggmp::{Participant, PartyOptions},
    k256::ecdsa::{
        self, signature::hazmat::PrehashVerifier, SigningKey,
        VerifyingKey,
    },
    synedrion::{SessionId, TestParams, ThresholdKeyShare},
};

use polysig_client::{
    cggmp::{dkg, sign},
    ServerOptions, SessionOptions,
};
use polysig_protocol::{Keypair, Parameters};
use rand::{rngs::OsRng, Rng};
use std::collections::BTreeSet;

use super::{make_signers, make_signing_message};

type KeyShare = ThresholdKeyShare<TestParams, VerifyingKey>;

pub async fn run_dkg_sign_2_2(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let t = 2;
    let n = 2;

    let (server, key_shares, signers) =
        run_dkg(t, n, server, server_public_key).await?;
    sign_t_2(t, n, server, key_shares, signers).await?;

    Ok(())
}

pub async fn run_dkg_sign_2_3(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let t = 2;
    let n = 3;

    let (server, key_shares, signers) =
        run_dkg(t, n, server, server_public_key).await?;
    sign_t_2(t, n, server, key_shares, signers).await?;

    Ok(())
}

pub(super) async fn run_dkg(
    t: u16,
    n: u16,
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<(ServerOptions, Vec<KeyShare>, Vec<SigningKey>)> {
    let params = Parameters {
        parties: n,
        threshold: t,
    };
    let (signers, verifiers) = make_signers(n as usize);
    let server = ServerOptions {
        server_url: server.to_owned(),
        server_public_key: server_public_key.clone(),
        pattern: None,
    };

    let rng = &mut OsRng;
    let keygen_session_id: [u8; 32] = rng.gen();
    let keygen_session_id = SessionId::from_seed(&keygen_session_id);

    let mut session_options = Vec::new();
    let mut public_keys = Vec::new();
    let mut keypairs = Vec::new();

    for _ in 0..n {
        let keypair = Keypair::generate()?;
        keypairs.push(keypair.clone());
        public_keys.push(keypair.public_key().to_vec());

        session_options.push(SessionOptions {
            keypair,
            parameters: params.clone(),
            server: server.clone(),
        });
    }

    let mut tasks = Vec::new();

    for (index, (opts, signer)) in session_options
        .into_iter()
        .zip(signers.clone().into_iter())
        .enumerate()
    {
        let participants =
            public_keys.iter().cloned().collect::<Vec<_>>();
        let is_initiator = index == 0;
        let public_key = participants.get(index).unwrap().to_vec();

        let party = PartyOptions::new(
            public_key,
            participants,
            is_initiator,
            verifiers.clone(),
        )?;

        let verifier = signer.verifying_key().clone();
        tasks.push(tokio::task::spawn(async move {
            let key_share = dkg(
                opts,
                Participant::new(signer, verifier, party)?,
                keygen_session_id.clone(),
            )
            .await?;
            Ok::<_, anyhow::Error>(key_share)
        }));
    }

    // Gather the key shares
    let mut key_shares = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        key_shares.push(result?.into());
    }

    Ok((server, key_shares, signers))
}

pub(super) async fn sign_t_2(
    t: u16,
    n: u16,
    server: ServerOptions,
    mut key_shares: Vec<KeyShare>,
    signers: Vec<SigningKey>,
) -> Result<()> {
    let params = Parameters {
        parties: n,
        threshold: t,
    };

    let message = make_signing_message()?;

    let mut keypairs = Vec::new();

    for _ in 0..t {
        let keypair = Keypair::generate()?;
        keypairs.push(keypair.clone());
    }

    // Prepare data for signing
    let rng = &mut OsRng;
    let sign_session_id: [u8; 32] = rng.gen();
    let sign_session_id = SessionId::from_seed(&sign_session_id);

    let selected_signers = vec![
        signers.first().unwrap().clone(),
        signers.last().unwrap().clone(),
    ];
    let selected_verifiers = selected_signers
        .iter()
        .map(|s| s.verifying_key().clone())
        .collect::<Vec<_>>();

    let first_share = key_shares.remove(0);
    let vkey = first_share.verifying_key().clone();

    let selected_key_shares =
        vec![first_share, key_shares.remove(key_shares.len() - 1)];
    let public_keys = vec![
        keypairs.first().unwrap().public_key().to_owned(),
        keypairs.last().unwrap().public_key().to_owned(),
    ];

    let session_options = vec![
        SessionOptions {
            keypair: keypairs.first().unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
        SessionOptions {
            keypair: keypairs.last().unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
    ];

    let mut tasks = Vec::new();
    for (index, ((opts, key_share), signer)) in session_options
        .into_iter()
        .zip(selected_key_shares.into_iter())
        .zip(selected_signers.into_iter())
        .enumerate()
    {
        let participants =
            public_keys.iter().cloned().collect::<Vec<_>>();
        let is_initiator = index == 0;
        let public_key = participants.get(index).unwrap().to_vec();

        let party = PartyOptions::new(
            public_key,
            participants,
            is_initiator,
            selected_verifiers.clone(),
        )?;

        let verifier = signer.verifying_key().clone();
        let participant = Participant::new(signer, verifier, party)?;
        let mut selected_parties = BTreeSet::new();
        selected_parties
            .extend(participant.party().verifiers().iter());
        let key_share = key_share.to_key_share(&selected_parties);

        tasks.push(tokio::task::spawn(async move {
            let signature = sign(
                opts,
                participant,
                sign_session_id.clone(),
                &key_share,
                &message,
            )
            .await?;
            Ok::<_, anyhow::Error>(signature)
        }));
    }

    // Gather the signatures
    let mut signatures = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        signatures.push(result?);
    }

    assert_eq!(t as usize, signatures.len());

    let mut ecdsa_signatures: Vec<(
        ecdsa::Signature,
        ecdsa::RecoveryId,
    )> = Vec::with_capacity(signatures.len());
    for sig in signatures {
        ecdsa_signatures.push(sig.try_into()?);
    }
    for (sig, rec_id) in ecdsa_signatures {
        // Check that the signature can be verified
        vkey.verify_prehash(&message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key =
            ecdsa::VerifyingKey::recover_from_prehash(
                &message, &sig, rec_id,
            )
            .unwrap();
        assert_eq!(recovered_key, vkey);
    }

    Ok(())
}
