use super::*;
use std::{
    process::{Command, Stdio},
    sync::mpsc,
};

const SCENARIO: &str = "ROP_TEST_WAKE_PROCESS_SCENARIO";

// Run the actual command renderer and exit boundary in an isolated process,
// with a channel-backed actor so no test can send a hardware wake packet.
#[test]
fn wake_process_fixture() {
    let Ok(scenario) = std::env::var(SCENARIO) else {
        return;
    };
    let (commands, command_rx) = mpsc::channel();
    let (events_tx, events) = mpsc::sync_channel(8);
    let handle = client::ClientHandle::from_channels(commands, events);
    let actor = thread::spawn(move || {
        let client::ClientCommand::Wake {
            operation_id,
            attempt,
            ..
        } = command_rx.recv_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("expected wake command");
        };
        if scenario == "disconnected" {
            events_tx.send(client::ClientEvent::Disconnected).unwrap();
            return;
        }
        if scenario == "timeout" {
            command_rx
                .recv_timeout(Duration::from_secs(20))
                .unwrap_err();
            return;
        }
        let results = ["alpha", "beta"]
            .into_iter()
            .map(|host| {
                let accepted = scenario == "complete" || (scenario == "partial" && host == "alpha");
                protocol::WakeResult {
                    host_id: host.into(),
                    accepted,
                    error_code: (!accepted).then_some(protocol::WakeErrorCode::RateLimited),
                }
            })
            .collect::<Vec<_>>();
        events_tx
            .send(client::ClientEvent::CommandExecuted {
                operation_id,
                attempt,
                retry_ticket: [1; 32],
                deadline_ms: client::now_ms() + 60_000,
                results: results.clone(),
            })
            .unwrap();
        for result in results.into_iter().filter(|result| result.accepted) {
            events_tx
                .send(client::ClientEvent::TargetOnline {
                    operation_id,
                    attempt,
                    host_id: result.host_id,
                })
                .unwrap();
        }
    });
    let result = run_wake_session(&handle, HashSet::from(["alpha".into(), "beta".into()]), 1);
    drop(handle);
    actor.join().unwrap();
    exit_on_error(result);
}

#[test]
fn wake_process_exit_status_and_redirected_output_match_outcome() {
    for (scenario, success, message) in [
        ("rejected", false, "服务端拒绝了全部目标"),
        ("partial", false, "部分目标被拒绝"),
        ("disconnected", false, "服务端已断开"),
        ("timeout", false, "等待服务端执行回执超时"),
        ("complete", true, "OK: 全部目标已上线"),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli_tests::wake_process_fixture", "--nocapture"])
            .env(SCENARIO, scenario)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "CLI scenario {scenario} exceeded process deadline: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.success(), success, "{scenario}: {text}");
        if !success {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {text}");
            assert!(!text.contains("OK:"), "{scenario}: {text}");
        }
        assert!(text.contains(message), "{scenario}: {text}");
        for forbidden in ["\x1b", "{RED}", "{GREEN}", "{RESET}"] {
            assert!(!text.contains(forbidden), "{scenario}: {text}");
        }
    }
}
