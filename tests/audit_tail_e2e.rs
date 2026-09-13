//! `audit tail -f` against the real binary.
//!
//! The property is that it is a stream and not a dump: lines have to reach the
//! reader while the process keeps running, which is exactly what an in-process
//! test of the reader cannot show.

use mcp_iap::audit::{AuditLog, AuditRecord};
use mcp_iap::config::AuditConfig;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

/// Generous: the follower polls a few times a second, and CI is not a quiet box.
const PATIENCE: Duration = Duration::from_secs(15);

fn open_log(path: &Path) -> AuditLog {
    AuditLog::open(
        &AuditConfig {
            path: path.to_path_buf(),
            stderr: false,
            ..Default::default()
        },
        false,
    )
    .unwrap()
}

fn record(log: &AuditLog, agent: &str, path: &str) {
    let mut record = AuditRecord::new("http", "request");
    record.agent = agent.to_string();
    record.target = "github".to_string();
    record.method = "GET".to_string();
    record.path = path.to_string();
    record.decision = Some("allow".to_string());
    log.write(record).unwrap();
}

/// A running `audit tail`, with its stdout pumped into a channel so the test
/// can wait for a line with a timeout instead of blocking forever on a read.
struct Tailer {
    child: Child,
    lines: Receiver<String>,
}

impl Tailer {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-iap"))
            .arg("audit")
            .arg("tail")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Tailer { child, lines }
    }

    fn next_line(&self, what: &str) -> String {
        match self.lines.recv_timeout(PATIENCE) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for {what}"),
            Err(RecvTimeoutError::Disconnected) => panic!("the follower exited before {what}"),
        }
    }

    fn nothing_within(&self, grace: Duration) -> Option<String> {
        self.lines.recv_timeout(grace).ok()
    }
}

impl Drop for Tailer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn follow_prints_the_tail_then_every_entry_as_it_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = open_log(&path);
    for index in 0..4 {
        record(&log, "bravo", &format!("/repos/{index}"));
    }

    let mut tailer = Tailer::spawn(&[path.to_str().unwrap(), "--follow", "-n", "2"]);

    // `-n` still bounds the dump; following starts after it.
    assert!(tailer.next_line("the dump").contains("/repos/2"));
    assert!(tailer.next_line("the dump").contains("/repos/3"));

    // The point of the whole exercise: written now, printed now, by a process
    // that was already running and stays running.
    record(&log, "bravo", "/repos/live");
    assert!(tailer.next_line("a live entry").contains("/repos/live"));

    record(&log, "bravo", "/repos/live-again");
    assert!(tailer
        .next_line("a second live entry")
        .contains("live-again"));

    assert!(
        tailer.child.try_wait().unwrap().is_none(),
        "a follower is a stream — it must still be running"
    );
}

#[test]
fn follow_applies_the_agent_filter_to_the_live_stream_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = open_log(&path);

    let tailer = Tailer::spawn(&[path.to_str().unwrap(), "-f", "--agent", "bravo"]);
    // Nothing is due yet, which also gives the follower time to reach its loop.
    assert_eq!(tailer.nothing_within(Duration::from_millis(500)), None);

    record(&log, "alpha", "/repos/alpha");
    record(&log, "bravo", "/repos/bravo");

    let line = tailer.next_line("bravo's entry");
    assert!(line.contains("/repos/bravo"), "{line}");
    assert!(
        !line.contains("alpha"),
        "a filtered follow must not leak another agent's traffic: {line}"
    );
}

#[test]
fn follow_waits_for_a_log_that_does_not_exist_yet() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    // Following is routinely started before the proxy that writes the log.
    let tailer = Tailer::spawn(&[path.to_str().unwrap(), "-f"]);
    assert_eq!(tailer.nothing_within(Duration::from_millis(500)), None);

    let log = open_log(&path);
    record(&log, "bravo", "/repos/first");
    assert!(tailer.next_line("the first entry").contains("/repos/first"));
}

#[test]
fn without_follow_it_dumps_and_exits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = open_log(&path);
    record(&log, "bravo", "/repos/one");
    record(&log, "bravo", "/repos/two");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-iap"))
        .args(["audit", "tail", path.to_str().unwrap(), "-n", "1"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("/repos/two"), "{stdout}");
}

#[test]
fn a_named_log_that_is_not_there_is_an_error_rather_than_silence() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-iap"))
        .args(["audit", "tail", missing.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no audit log at"), "{stderr}");
}
