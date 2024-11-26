use anyhow::Result;
use polysig_protocol::{PublicKeys, UserId};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use polysig_client::meeting;

pub async fn run(server: &str, num_participants: u8) -> Result<u8> {
    // Identifiers can be any arbitrary value, in the real world
    // this might be the hash of a nickname or email address
    let init_id: [u8; 32] =
        Sha256::digest("initiator".as_bytes()).try_into().unwrap();
    let init_id: UserId = init_id.into();

    let mut owner_id = None;
    let mut join_ids: HashSet<UserId> = HashSet::new();
    for i in 0..num_participants {
        let part_id =
            Sha256::digest(format!("participant_{}", i).as_bytes());
        let part_id: [u8; 32] = part_id.try_into().unwrap();
        let user_id: UserId = part_id.try_into()?;
        if i == 0 {
            owner_id = Some(user_id.clone());
        }
        join_ids.insert(user_id);
    }

    // Prepare enough slots for all participants
    let mut slots = HashSet::new();
    slots.insert(init_id.clone());
    for id in &join_ids {
        slots.insert(id.clone());
    }

    let meeting_id = meeting::create(
        server,
        join_ids.clone().into_iter().collect::<Vec<_>>(),
        owner_id.unwrap(),
    )
    .await?;

    let mut tasks = Vec::new();
    for (index, user_id) in join_ids.into_iter().enumerate() {
        let server_url = server.to_owned();
        tasks.push(tokio::task::spawn(async move {
            let value = PublicKeys {
                public_key: vec![index as u8 + 1],
                verifying_key: vec![index as u8 + 1],
                associated_data: None,
            };

            let results = meeting::join(
                &server_url,
                meeting_id.clone(),
                user_id,
                value,
            )
            .await?;

            Ok::<_, anyhow::Error>(results)
        }));
    }

    let mut parties = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    let num_results = results.len();
    for result in results {
        let participants = result?;
        parties.push(participants);
    }

    let all_equal = parties.windows(2).all(|w| w[0] == w[1]);
    assert!(all_equal);

    Ok(num_results as u8)
}
