//! Key generation for FROST Ed25519.
use frost_ed25519::{keys::dkg, Identifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, num::NonZeroU16};

use crate::{
    frost::{Error, Result},
    ProtocolDriver, RoundInfo, RoundMessage,
};

use super::{KeyShare, ROUND_1, ROUND_2, ROUND_3};

#[derive(Debug, Serialize, Deserialize)]
pub enum DkgPackage {
    Round1(dkg::round1::Package),
    Round2(dkg::round2::Package),
}

/// FROST keygen driver.
pub struct KeyGenDriver {
    #[allow(dead_code)]
    party_number: NonZeroU16,
    max_signers: u16,
    min_signers: u16,
    identifiers: Vec<Identifier>,
    id: Identifier,
    round_number: u8,
    round1_package: Option<dkg::round1::SecretPackage>,
    received_round1_packages:
        BTreeMap<Identifier, dkg::round1::Package>,

    round2_package: Option<dkg::round2::SecretPackage>,
    received_round2_packages:
        BTreeMap<Identifier, dkg::round2::Package>,
}

impl KeyGenDriver {
    /// Create a key generator.
    pub fn new(
        party_number: NonZeroU16,
        max_signers: u16,
        min_signers: u16,
        identifiers: Vec<Identifier>,
    ) -> Result<Self> {
        let party_index: usize = party_number.get() as usize;
        let self_index = party_index - 1;
        let id = *identifiers
            .get(self_index)
            .ok_or(Error::IndexIdentifier(party_index))?;

        Ok(Self {
            party_number,
            max_signers,
            min_signers,
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

impl ProtocolDriver for KeyGenDriver {
    type Error = Error;
    type Message = RoundMessage<DkgPackage, Identifier>;
    type Output = KeyShare;

    fn round_info(&self) -> Result<RoundInfo> {
        let needs = self.identifiers.len() - 1;
        let round_number = self.round_number;
        let is_echo = false;
        let can_finalize = match self.round_number {
            ROUND_2 => self.received_round1_packages.len() == needs,
            ROUND_3 => self.received_round2_packages.len() == needs,
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
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let (private_package, public_package) = dkg::part1(
                    self.id.clone(),
                    self.max_signers,
                    self.min_signers,
                    &mut OsRng,
                )?;

                self.round1_package = Some(private_package);

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    if id == &self.id {
                        continue;
                    }

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();

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
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let round1_secret_package = self
                    .round1_package
                    .take()
                    .ok_or(Error::Round2TooEarly)?;

                let (round2_secret_package, round2_packages) =
                    dkg::part2(
                        round1_secret_package,
                        &self.received_round1_packages,
                    )?;

                self.round2_package = Some(round2_secret_package);

                for (receiver_id, package) in round2_packages {
                    let index = self
                        .identifiers
                        .iter()
                        .position(|i| i == &receiver_id)
                        .unwrap();

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();

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

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        if self.round_number == ROUND_3
            && self.received_round2_packages.len()
                == self.identifiers.len() - 1
        {
            let round2_secret_package = self
                .round2_package
                .take()
                .ok_or(Error::Round3TooEarly)?;

            let result = dkg::part3(
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
