macro_rules! frost_dkg_sign {
    () => {
        pub(crate) struct SelectedSigners {
            /// Keypairs for the noise transport.
            pub keypairs: Vec<Keypair>,
            /// Transport public keys.
            pub public_keys: Vec<Vec<u8>>,
            /// Signer and all verifying keys.
            pub signers: Vec<(SigningKey, Vec<VerifyingKey>)>,
            /// Identifiers extracted from the key shares.
            pub identifiers: Vec<Identifier>,
            /// Selected key shares.
            pub key_shares: Vec<KeyShare>,
        }

        impl SelectedSigners {
            pub fn new(
                t: u16,
                indices: &[usize],
                signers: Vec<SigningKey>,
                key_shares: Vec<KeyShare>,
            ) -> Result<Self> {
                let mut keypairs = Vec::new();
                for _ in 0..t {
                    let keypair = Keypair::generate()?;
                    keypairs.push(keypair);
                }

                let public_keys = keypairs
                    .iter()
                    .map(|k| k.public_key().to_owned())
                    .collect::<Vec<_>>();

                let selected_signers = indices
                    .iter()
                    .map(|i| signers.get(*i).unwrap().clone())
                    .collect::<Vec<_>>();
                let selected_verifiers = selected_signers
                    .iter()
                    .map(|s| s.verifying_key().clone())
                    .collect::<Vec<_>>();

                let selected_key_shares = indices
                    .iter()
                    .map(|i| key_shares.get(*i).unwrap().clone())
                    .collect::<Vec<_>>();
                let identifiers = selected_key_shares
                    .iter()
                    .map(|s| s.0.identifier().clone())
                    .collect::<Vec<_>>();

                Ok(SelectedSigners {
                    keypairs,
                    public_keys,
                    signers: selected_signers
                        .into_iter()
                        .map(|s| (s, selected_verifiers.clone()))
                        .collect(),
                    key_shares: selected_key_shares,
                    identifiers,
                })
            }
        }

        pub async fn run_dkg_sign_2_3(
            server: &str,
            server_public_key: Vec<u8>,
        ) -> Result<()> {
            run_dkg_sign(2, 3, server, server_public_key, &[0, 2])
                .await
        }

        pub async fn run_dkg_sign_3_5(
            server: &str,
            server_public_key: Vec<u8>,
        ) -> Result<()> {
            run_dkg_sign(3, 5, server, server_public_key, &[0, 1, 4])
                .await
        }

        pub async fn run_dkg_sign_5_9(
            server: &str,
            server_public_key: Vec<u8>,
        ) -> Result<()> {
            run_dkg_sign(
                5,
                9,
                server,
                server_public_key,
                &[0, 1, 4, 6, 8],
            )
            .await
        }

        pub async fn run_dkg_sign(
            t: u16,
            n: u16,
            server: &str,
            server_public_key: Vec<u8>,
            indices: &[usize],
        ) -> Result<()> {
            let (server, key_shares, signers) =
                run_dkg(t, n, server, server_public_key).await?;

            // println!("dkg completed {}", key_shares.len());

            let selected = SelectedSigners::new(
                t,
                indices,
                signers,
                key_shares.clone(),
            )?;

            check_sign(t, n, server, key_shares, selected).await?;

            Ok(())
        }

        pub async fn check_sign(
            t: u16,
            n: u16,
            server: ServerOptions,
            all_key_shares: Vec<KeyShare>,
            selected: SelectedSigners,
        ) -> Result<()> {
            // Prepare group public key for verification after signing
            let verifying_keys = all_key_shares
                .iter()
                .map(|k| {
                    (
                        k.0.identifier().clone(),
                        k.0.verifying_share().to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let verifying_key = all_key_shares
                .first()
                .unwrap()
                .0
                .verifying_key()
                .to_owned();
            let pubkey_package = keys::PublicKeyPackage::new(
                verifying_keys,
                verifying_key,
            );

            let params = Parameters {
                parties: n,
                threshold: t,
            };

            let message = make_signing_message();

            let session_options = selected
                .keypairs
                .iter()
                .map(|keypair| SessionOptions {
                    keypair: keypair.clone(),
                    parameters: params.clone(),
                    server: server.clone(),
                })
                .collect::<Vec<_>>();

            let mut tasks = Vec::new();
            for (index, ((opts, key_share), (signer, verifiers))) in
                session_options
                    .into_iter()
                    .zip(selected.key_shares.into_iter())
                    .zip(selected.signers.into_iter())
                    .enumerate()
            {
                let participants = selected
                    .public_keys
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                let is_initiator = index == 0;
                let public_key =
                    participants.get(index).unwrap().to_vec();

                let party = PartyOptions::new(
                    public_key,
                    participants,
                    is_initiator,
                    verifiers,
                )?;

                let verifier = signer.verifying_key().clone();
                let participant =
                    Participant::new(signer, verifier, party)?;
                let msg = message.clone();
                let ids = selected.identifiers.clone();

                tasks.push(tokio::task::spawn(async move {
                    let signature =
                        sign(opts, participant, ids, key_share, msg)
                            .await?;
                    Ok::<_, anyhow::Error>(signature)
                }));
            }

            // Gather the signatures
            let mut signatures = Vec::new();
            let results =
                futures::future::try_join_all(tasks).await?;
            for result in results {
                signatures.push(result?);
            }
            assert_eq!(t as usize, signatures.len());

            for sig in &signatures {
                // Check that the threshold signature can be verified by
                // the group public key (the verification key).
                pubkey_package
                    .verifying_key()
                    .verify(&message, &sig)?;
                // Check that the threshold signature can be verified by
                // the group public key (the verification key) from
                // KeyPackage.verifying_key
                for key_share in &all_key_shares {
                    key_share
                        .1
                        .verifying_key()
                        .verify(&message, sig)?;
                }
            }

            Ok(())
        }
    };
}

pub(crate) use frost_dkg_sign;
