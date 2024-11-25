use anyhow::Result;

use crate::test_utils::{meeting_point, spawn_meeting_server};

/// Test creating and joining a meeting point.
#[tokio::test]
async fn integration_meeting_point() -> Result<()> {
    crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_meeting_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);
    let expected_participants = 5u8;
    let connected_participants =
        meeting_point::run(&server, expected_participants).await?;
    assert_eq!(expected_participants, connected_participants);

    Ok(())
}
