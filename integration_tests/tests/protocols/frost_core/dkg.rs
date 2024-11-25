macro_rules! frost_dkg {
    () => {
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
                let public_key =
                    participants.get(index).unwrap().to_vec();

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
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(key_share)
                }));
            }

            // Gather the key shares
            let mut key_shares = Vec::new();
            let results =
                futures::future::try_join_all(tasks).await?;
            for result in results {
                key_shares.push(result?.into());
            }

            Ok((server, key_shares, signers))
        }
    };
}

pub(crate) use frost_dkg;
