//! Bindings for meeting points.
use super::types::{MeetingItem, PublicKeys, UserId};
use anyhow::Result;
use napi_derive::napi;
use polysig_client::meeting;
use polysig_protocol as protocol;

/// Create and join meeting rooms.
#[napi]
pub struct MeetingRoom {
    url: String,
}

#[napi]
impl MeetingRoom {
    /// Create a meeting room.
    #[napi(constructor)]
    pub fn new(url: String) -> MeetingRoom {
        Self { url }
    }

    /// Create a meeting room used to exchange public keys.
    #[napi]
    pub async fn create(
        &self,
        identifiers: Vec<UserId>,
        initiator: UserId,
    ) -> Result<String> {
        let mut ids = Vec::with_capacity(identifiers.len());
        for id in identifiers {
            ids.push(id.try_into()?);
        }

        Ok(meeting::create(&self.url, ids, initiator.try_into()?)
            .await?
            .to_string())
    }

    /// Join a meeting room used to exchange public keys.
    #[napi]
    pub async fn join(
        &self,
        meeting_id: String,
        user_id: UserId,
        data: PublicKeys,
    ) -> Result<Vec<MeetingItem>> {
        let meeting_id: protocol::MeetingId = meeting_id.parse()?;
        let results = meeting::join(
            &self.url,
            meeting_id,
            user_id.try_into()?,
            data.into(),
        )
        .await?;

        let mut output = Vec::with_capacity(results.len());
        for result in results {
            output.push(MeetingItem {
                user_id: result.0.into(),
                data: result.1.into(),
            })
        }

        Ok(output)
    }
}
