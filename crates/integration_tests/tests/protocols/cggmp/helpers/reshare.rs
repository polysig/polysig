use anyhow::Result;
use polysig_client::{
    cggmp::{dkg, reshare, sign},
    ServerOptions, SessionOptions,
};
use polysig_driver::{
    cggmp::{Participant, PartyOptions},
    k256::ecdsa::{
        self, signature::hazmat::PrehashVerifier, SigningKey,
        VerifyingKey,
    },
    synedrion::{SessionId, TestParams, ThresholdKeyShare},
};
use polysig_protocol::{Keypair, Parameters};
use rand::{rngs::OsRng, Rng};
use std::collections::BTreeSet;

use super::{make_signers, make_signing_message};

type KeyShare = ThresholdKeyShare<TestParams, VerifyingKey>;

pub async fn run_dkg_reshare_2_2_to_3_4(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 2;
    let t = 2;
    let key_shares =
        run_dkg(t, n, server, &server_public_key).await?;

    assert_eq!(n as usize, key_shares.len());

    let new_t = 3;
    let new_n = 4;

    let (new_key_shares, new_signers) = run_reshare(
        server,
        &server_public_key,
        key_shares,
        t as usize,
        new_t,
        new_n,
    )
    .await?;

    assert_eq!(new_n, new_key_shares.len());

    run_sign(
        new_t as u16,
        new_n as u16,
        server,
        &server_public_key,
        new_signers,
        new_key_shares,
    )
    .await?;

    Ok(())
}

async fn run_dkg(
    t: u16,
    n: u16,
    server: &str,
    server_public_key: &[u8],
) -> Result<Vec<KeyShare>> {
    let params = Parameters {
        parties: n,
        threshold: t,
    };
    let (signers, verifiers) = make_signers(n as usize);
    let server = ServerOptions {
        server_url: server.to_owned(),
        server_public_key: server_public_key.to_vec(),
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

    Ok(key_shares)
}

async fn run_reshare(
    server: &str,
    server_public_key: &[u8],
    old_holders: Vec<KeyShare>,
    old_t: usize,
    new_t: usize,
    new_n: usize,
) -> Result<(Vec<KeyShare>, Vec<SigningKey>)> {
    let old_keys = old_holders.clone();

    let account_verifying_key =
        old_keys.first().unwrap().verifying_key().to_owned();

    let params = Parameters {
        parties: new_n as u16,
        threshold: new_t as u16,
    };

    let (signers, verifiers) = make_signers(new_n as usize);
    let server = ServerOptions {
        server_url: server.to_owned(),
        server_public_key: server_public_key.to_vec(),
        pattern: None,
    };

    let rng = &mut OsRng;
    let keygen_session_id: [u8; 32] = rng.gen();
    let keygen_session_id = SessionId::from_seed(&keygen_session_id);

    let mut session_options = Vec::new();
    let mut public_keys = Vec::new();
    let mut keypairs = Vec::new();

    for _ in 0..new_n {
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

        let key_share = old_keys.get(index).cloned();

        let verifier = signer.verifying_key().clone();
        tasks.push(tokio::task::spawn(async move {
            let key_share = reshare(
                opts,
                Participant::new(signer, verifier, party)?,
                keygen_session_id.clone(),
                account_verifying_key.clone(),
                key_share,
                old_t,
                new_t,
            )
            .await?;
            Ok::<_, anyhow::Error>(key_share)
        }));
    }

    // Gather the key shares
    let mut key_shares = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        key_shares.push(result?);
    }

    Ok((key_shares, signers))
}

async fn run_sign(
    t: u16,
    n: u16,
    server: &str,
    server_public_key: &[u8],
    mut signers: Vec<SigningKey>,
    key_shares: Vec<KeyShare>,
) -> Result<()> {
    let params = Parameters {
        parties: n,
        threshold: t,
    };
    let rng = &mut OsRng;
    let message = make_signing_message()?;

    let server = ServerOptions {
        server_url: server.to_owned(),
        server_public_key: server_public_key.to_vec(),
        pattern: None,
    };

    let mut keys = key_shares.clone();

    let mut session_options = Vec::new();
    let mut public_keys = Vec::new();
    let mut keypairs = Vec::new();

    for _ in 0..t {
        let keypair = Keypair::generate()?;
        keypairs.push(keypair.clone());
        public_keys.push(keypair.public_key().to_vec());

        session_options.push(SessionOptions {
            keypair,
            parameters: params.clone(),
            server: server.clone(),
        });
    }

    // Prepare data for signing
    let sign_session_id: [u8; 32] = rng.gen();
    let sign_session_id = SessionId::from_seed(&sign_session_id);

    let first_signer = signers.remove(0);
    let second_signer = signers.remove(0);
    let last_signer = signers.remove(signers.len() - 1);

    let selected_signers =
        vec![first_signer, second_signer, last_signer];
    let selected_verifiers = selected_signers
        .iter()
        .map(|s| s.verifying_key().clone())
        .collect::<Vec<_>>();

    let first_share = keys.remove(0);
    let second_share = keys.remove(0);
    let last_share = keys.remove(keys.len() - 1);

    let vkey = first_share.verifying_key().clone();

    let first_keypair = keypairs.remove(0);
    let second_keypair = keypairs.remove(0);
    let last_keypair = keypairs.remove(keypairs.len() - 1);

    let selected_key_shares =
        vec![first_share, second_share, last_share];

    let public_keys = vec![
        first_keypair.public_key().to_owned(),
        second_keypair.public_key().to_owned(),
        last_keypair.public_key().to_owned(),
    ];

    let session_options = vec![
        SessionOptions {
            keypair: first_keypair.clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
        SessionOptions {
            keypair: second_keypair.clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
        SessionOptions {
            keypair: last_keypair.clone(),
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
