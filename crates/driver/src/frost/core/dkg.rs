//! Macro to generate DKG driver for FROST.
macro_rules! frost_dkg_impl {
    ($r1pub:ty,
     $r1priv:ty,
     $r2pub:ty,
     $r2priv:ty,
     $id:ty,
     $out:ty,
     $part1:ident,
     $part2:ident,
     $part3:ident) => {
        #[derive(Debug, Serialize, Deserialize)]
        pub enum DkgPackage {
            Round1($r1pub),
            Round2($r2pub),
        }

        /// FROST keygen driver.
        pub struct DkgDriver {
            #[allow(dead_code)]
            party_number: NonZeroU16,
            params: Parameters,
            identifiers: Vec<$id>,
            id: Identifier,
            round_number: u8,

            round1_package: Option<$r1priv>,
            received_round1_packages: BTreeMap<$id, $r1pub>,

            round2_package: Option<$r2priv>,
            received_round2_packages: BTreeMap<$id, $r2pub>,
        }

        impl DkgDriver {
            /// Create a key generator.
            pub fn new(
                party_number: NonZeroU16,
                params: Parameters,
                identifiers: Vec<$id>,
            ) -> Result<Self> {
                let party_index: usize = party_number.get() as usize;
                let self_index = party_index - 1;
                let id = *identifiers
                    .get(self_index)
                    .ok_or(Error::IndexIdentifier(party_index))?;

                Ok(Self {
                    party_number,
                    params,
                    identifiers,
                    id,
                    round_number: ROUND_1,

                    round1_package: None,
                    received_round1_packages: BTreeMap::new(),

                    round2_package: None,
                    received_round2_packages: BTreeMap::new(),
                })
            }
        }

        impl ProtocolDriver for DkgDriver {
            type Error = Error;
            type Message = RoundMessage<DkgPackage, $id>;
            type Output = $out;

            fn round_info(&self) -> Result<RoundInfo> {
                let needs = self.identifiers.len() - 1;
                let round_number = self.round_number;
                let is_echo = false;
                let can_finalize = match self.round_number {
                    ROUND_2 => {
                        self.received_round1_packages.len() == needs
                    }
                    ROUND_3 => {
                        self.received_round2_packages.len() == needs
                    }
                    _ => false,
                };
                Ok(RoundInfo {
                    round_number,
                    can_finalize,
                    is_echo,
                })
            }

            fn proceed(&mut self) -> Result<Vec<Self::Message>> {
                match self.round_number {
                    // Round 1 is a broadcast round, same package
                    // is sent to all other participants
                    ROUND_1 => {
                        let mut messages = Vec::with_capacity(
                            self.identifiers.len() - 1,
                        );

                        let (private_package, public_package) =
                            $part1(
                                self.id.clone(),
                                self.params.parties,
                                self.params.threshold,
                                &mut OsRng,
                            )?;

                        self.round1_package = Some(private_package);

                        for (index, id) in
                            self.identifiers.iter().enumerate()
                        {
                            if id == &self.id {
                                continue;
                            }

                            let receiver =
                                NonZeroU16::new((index + 1) as u16)
                                    .unwrap();

                            let message = RoundMessage {
                                round: NonZeroU16::new(
                                    self.round_number.into(),
                                )
                                .unwrap(),
                                sender: self.id.clone(),
                                receiver,
                                body: DkgPackage::Round1(
                                    public_package.clone(),
                                ),
                            };

                            messages.push(message);
                        }

                        self.round_number =
                            self.round_number.checked_add(1).unwrap();

                        Ok(messages)
                    }
                    // Round 2 is a p2p round, different package
                    // for each of the other participants
                    ROUND_2 => {
                        let mut messages = Vec::with_capacity(
                            self.identifiers.len() - 1,
                        );

                        let round1_secret_package = self
                            .round1_package
                            .take()
                            .ok_or(Error::Round2TooEarly)?;

                        let (round2_secret_package, round2_packages) =
                            $part2(
                                round1_secret_package,
                                &self.received_round1_packages,
                            )?;

                        self.round2_package =
                            Some(round2_secret_package);

                        for (receiver_id, package) in round2_packages
                        {
                            let index = self
                                .identifiers
                                .iter()
                                .position(|i| i == &receiver_id)
                                .unwrap();

                            let receiver =
                                NonZeroU16::new((index + 1) as u16)
                                    .unwrap();

                            let message = RoundMessage {
                                round: NonZeroU16::new(
                                    self.round_number.into(),
                                )
                                .unwrap(),
                                sender: self.id.clone(),
                                receiver,
                                body: DkgPackage::Round2(package),
                            };

                            messages.push(message);
                        }

                        self.round_number =
                            self.round_number.checked_add(1).unwrap();

                        Ok(messages)
                    }
                    _ => Err(Error::InvalidRound(self.round_number)),
                }
            }

            fn handle_incoming(
                &mut self,
                message: Self::Message,
            ) -> Result<()> {
                let round_number = message.round.get() as u8;
                match round_number {
                    ROUND_1 => match message.body {
                        DkgPackage::Round1(package) => {
                            let party_index = self
                                .identifiers
                                .iter()
                                .position(|v| v == &message.sender)
                                .ok_or(Error::SenderVerifier)?;
                            if let Some(id) =
                                self.identifiers.get(party_index)
                            {
                                self.received_round1_packages
                                    .insert(id.clone(), package);

                                Ok(())
                            } else {
                                Err(Error::SenderIdentifier(
                                    round_number,
                                    party_index,
                                ))
                            }
                        }
                        _ => Err(Error::RoundPayload(round_number)),
                    },
                    ROUND_2 => match message.body {
                        DkgPackage::Round2(package) => {
                            let party_index = self
                                .identifiers
                                .iter()
                                .position(|v| v == &message.sender)
                                .ok_or(Error::SenderVerifier)?;
                            if let Some(id) =
                                self.identifiers.get(party_index)
                            {
                                self.received_round2_packages
                                    .insert(id.clone(), package);
                                Ok(())
                            } else {
                                Err(Error::SenderIdentifier(
                                    round_number,
                                    party_index,
                                ))
                            }
                        }
                        _ => Err(Error::RoundPayload(round_number)),
                    },
                    _ => Err(Error::InvalidRound(round_number)),
                }
            }

            fn try_finalize_round(
                &mut self,
            ) -> Result<Option<Self::Output>> {
                if self.round_number == ROUND_3
                    && self.received_round2_packages.len()
                        == self.identifiers.len() - 1
                {
                    let round2_secret_package = self
                        .round2_package
                        .take()
                        .ok_or(Error::Round3TooEarly)?;

                    let result = $part3(
                        &round2_secret_package,
                        &self.received_round1_packages,
                        &self.received_round2_packages,
                    )?;
                    Ok(Some(result))
                } else {
                    Ok(None)
                }
            }
        }
    };
}

pub(crate) use frost_dkg_impl;
