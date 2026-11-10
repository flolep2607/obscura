//! OBSCURA_EXIT_WHEN_IDLE=1: the server exits once its last CDP connection closes, so a launcher
//! whose kill is refused (an AppArmor profile that denies the signal) still gets its process back.
//! nextest runs each test in its own process, so the env var stays local to the test.

use std::time::Duration;

use futures_util::SinkExt;
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Start a server, open and close one CDP connection, and say whether the server returned.
async fn server_returns_after_client_leaves(exit_when_idle: bool) -> bool {
    if exit_when_idle {
        // SAFETY: set before the server starts, in a test process of its own.
        unsafe { std::env::set_var("OBSCURA_EXIT_WHEN_IDLE", "1") };
    }
    let dir = std::env::temp_dir().join(format!("obscura-exit-when-idle-{}-{exit_when_idle}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ready = dir.join("ready.json");
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let ready_file = ready.clone();
            let server = tokio::task::spawn_local(async move {
                obscura_cdp::server::start_with_serve_options_limit_and_ready_file(
                    0, "127.0.0.1", None, false, None, false, None, true, 8, Some(&ready_file),
                )
                .await
                .unwrap();
            });
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !ready.exists() {
                assert!(tokio::time::Instant::now() < deadline, "server did not start");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let address: Value = serde_json::from_slice(&std::fs::read(&ready).unwrap()).unwrap();
            let endpoint = format!("ws://127.0.0.1:{}/devtools/browser", address["port"].as_u64().unwrap());
            let (mut ws, _) = connect_async(&endpoint).await.unwrap();
            ws.send(Message::Text(r#"{"id":1,"method":"Browser.getVersion","params":{}}"#.into())).await.unwrap();
            ws.close(None).await.unwrap();
            drop(ws);
            tokio::time::timeout(Duration::from_secs(10), server).await.is_ok()
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn the_server_exits_when_its_last_client_disconnects() {
    assert!(server_returns_after_client_leaves(true).await, "server kept running after its only client left");
}

#[tokio::test(flavor = "current_thread")]
async fn without_the_switch_the_server_keeps_running() {
    assert!(!server_returns_after_client_leaves(false).await, "server exited without OBSCURA_EXIT_WHEN_IDLE");
}
