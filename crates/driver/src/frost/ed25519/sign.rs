//! Signature generation for FROST.
use frost_ed25519::{
    aggregate,
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU16;

use crate::{
    frost::{Error, Result},
    ProtocolDriver, RoundInfo, RoundMessage,
};

use super::KeyShare;
use crate::frost::{
    core::sign::frost_sign_impl, ROUND_1, ROUND_2, ROUND_3,
};

frost_sign_impl!(
    SigningCommitments,
    SigningNonces,
    SignatureShare,
    SigningPackage,
    Identifier,
    Signature,
    round1,
    round2,
    aggregate
);

// Round1(SigningCommitments),
// Round2(SignatureShare),

/*
#[derive(Debug, Serialize, Deserialize)]
pub enum SignPackage {
    Round1(SigningCommitments),
    Round2(SignatureShare),
}

/// FROST signature driver.
pub struct SignatureDriver {
    #[allow(dead_code)]
    party_number: NonZeroU16,
    identifiers: Vec<Identifier>,
    id: Identifier,
    min_signers: u16,
    round_number: u8,
    key_share: KeyShare,
    message: Vec<u8>,
    nonces: Option<SigningNonces>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    signing_package: Option<SigningPackage>,
    signature_shares: BTreeMap<Identifier, SignatureShare>,
}

impl SignatureDriver {
    /// Create a driver.
    pub fn new(
        party_number: NonZeroU16,
        identifiers: Vec<Identifier>,
        min_signers: u16,
        key_share: KeyShare,
        message: Vec<u8>,
    ) -> Result<Self> {
        let party_index: usize = party_number.get() as usize;
        let self_index = party_index - 1;
        let id = *identifiers
            .get(self_index)
            .ok_or(Error::IndexIdentifier(party_index))?;

        Ok(Self {
            party_number,
            identifiers,
            id,
            min_signers,
            round_number: ROUND_1,
            key_share,
            message,
            nonces: None,
            commitments: BTreeMap::new(),
            signing_package: None,
            signature_shares: BTreeMap::new(),
        })
    }
}

impl ProtocolDriver for SignatureDriver {
    type Error = Error;
    type Message = RoundMessage<SignPackage, Identifier>;
    type Output = Signature;

    fn round_info(&self) -> Result<RoundInfo> {
        let round_number = self.round_number;
        let is_echo = false;
        let can_finalize = match self.round_number {
            ROUND_2 => {
                self.commitments.len() == self.min_signers as usize
            }
            // ROUND_3 => self.signing_package.is_some(),
            ROUND_3 => {
                self.signature_shares.len()
                    == self.min_signers as usize
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
            ROUND_1 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let (nonces, commitments) = round1::commit(
                    self.key_share.0.signing_share(),
                    &mut OsRng,
                );

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
                        body: SignPackage::Round1(
                            commitments.clone(),
                        ),
                    };

                    messages.push(message);
                }

                self.nonces = Some(nonces);
                self.commitments.insert(self.id.clone(), commitments);

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            ROUND_2 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let nonces = self
                    .nonces
                    .take()
                    .ok_or(Error::Round3TooEarly)?;

                let signing_package = SigningPackage::new(
                    self.commitments.clone(),
                    &self.message,
                );

                let signature_share = round2::sign(
                    &signing_package,
                    &nonces,
                    &self.key_share.0,
                )?;

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
                        body: SignPackage::Round2(
                            signature_share.clone(),
                        ),
                    };

                    messages.push(message);
                }

                self.signing_package = Some(signing_package);
                self.signature_shares
                    .insert(self.id.clone(), signature_share);

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
                SignPackage::Round1(commitments) => {
                    let party_index = self
                        .identifiers
                        .iter()
                        .position(|v| v == &message.sender)
                        .ok_or(Error::SenderVerifier)?;
                    if let Some(id) =
                        self.identifiers.get(party_index)
                    {
                        self.commitments
                            .insert(id.clone(), commitments);
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
                SignPackage::Round2(signature_share) => {
                    let party_index = self
                        .identifiers
                        .iter()
                        .position(|v| v == &message.sender)
                        .ok_or(Error::SenderVerifier)?;
                    if let Some(id) =
                        self.identifiers.get(party_index)
                    {
                        self.signature_shares
                            .insert(id.clone(), signature_share);
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
            && self.signature_shares.len()
                == self.min_signers as usize
        {
            let signing_package = self
                .signing_package
                .take()
                .ok_or(Error::Round3TooEarly)?;

            let group_signature = aggregate(
                &signing_package,
                &self.signature_shares,
                &self.key_share.1,
            )?;

            Ok(Some(group_signature))
        } else {
            Ok(None)
        }
    }
}
*/
