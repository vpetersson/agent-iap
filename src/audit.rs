//! The audit log.
//!
//! Every decision the proxy makes lands here as one JSON object per line. The
//! records are hash-chained: each line commits to the one before it, so a later
//! edit or deletion is detectable with `agent-iap audit verify`. Bodies are off by
//! default and credential-bearing headers are redacted before anything is written.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened. `event` names the stage, `decision` names the ACL outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditRecord {
    /// `http` or `mcp`.
    pub kind: String,
    /// `request`, `denied`, `error`, `startup`, `approval`.
    pub event: String,
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// Which of the agent's workload tokens made the call: `lineage/generation`.
    /// Absent for a bare agent token, which is how a log shows at a glance how
    /// much of its traffic still runs on a standing grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    pub target: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Anything scheme-specific: redacted headers, truncated bodies, JSON-RPC ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl AuditRecord {
    pub fn new(kind: &str, event: &str) -> Self {
        AuditRecord {
            kind: kind.to_string(),
            event: event.to_string(),
            ..Default::default()
        }
    }
}

/// A record once the log has sequenced and chained it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub id: String,
    pub ts: String,
    #[serde(flatten)]
    pub record: AuditRecord,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEvent {
    /// Recompute this entry's hash from its contents and the chain so far.
    fn compute_hash(&self) -> String {
        let mut unhashed = self.clone();
        unhashed.hash = String::new();
        let canonical =
            serde_json::to_string(&unhashed).expect("audit event is always serialisable");
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }

    /// Whether this entry is in scope for a filtered view of the log.
    ///
    /// One proxy fronts many agents, so a log is interleaved by construction and
    /// reading it usually means narrowing it to one of them.
    pub fn matches(&self, agent: Option<&str>, target: Option<&str>) -> bool {
        agent.is_none_or(|id| self.record.agent == id)
            && target.is_none_or(|name| self.record.target == name)
    }

    /// A single line for the TUI feed and for `--stderr` output.
    pub fn oneline(&self) -> String {
        let decision = self
            .record
            .decision
            .as_deref()
            .unwrap_or(&self.record.event);
        let status = self
            .record
            .status
            .map(|s| format!(" {s}"))
            .unwrap_or_default();
        let duration = self
            .record
            .duration_ms
            .map(|d| format!(" {d}ms"))
            .unwrap_or_default();
        format!(
            "[{}] {} {} {} {} {}{}{}",
            decision,
            self.record.agent,
            self.record.kind,
            self.record.target,
            self.record.method,
            self.record.path,
            status,
            duration
        )
    }
}

pub struct AuditLog {
    inner: Mutex<Writer>,
    events: broadcast::Sender<AuditEvent>,
    /// What to redact and how much to keep, replaceable while running. The
    /// file this is written to is replaceable too — see `reopen`.
    settings: RwLock<Settings>,
    stderr: bool,
}

struct Settings {
    path: PathBuf,
    redact: HashSet<String>,
    max_logged_body_bytes: usize,
    log_bodies: bool,
    log_mcp_params: bool,
}

impl Settings {
    fn from(config: &crate::config::AuditConfig) -> Self {
        Settings {
            path: config.path.clone(),
            redact: config
                .redact_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            max_logged_body_bytes: config.max_logged_body_bytes,
            log_bodies: config.log_bodies,
            log_mcp_params: config.log_mcp_params,
        }
    }
}

struct Writer {
    file: BufWriter<File>,
    seq: u64,
    prev_hash: String,
}

/// Open the log at `config.path`, picking up whatever chain is already there.
///
/// Resuming rather than restarting is what lets `agent-iap audit verify` span a
/// restart: the first record after one is the next link, not a new genesis.
fn open_chain(config: &crate::config::AuditConfig) -> Result<Writer> {
    if let Some(parent) = config.path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::paths::ensure_dir(parent)
                .with_context(|| format!("creating audit directory `{}`", parent.display()))?;
        }
    }

    let (seq, prev_hash) = match read_tail(&config.path)? {
        Some(last) => (last.seq + 1, last.hash),
        None => (0, GENESIS_HASH.to_string()),
    };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.path)
        .with_context(|| format!("opening audit log `{}`", config.path.display()))?;

    Ok(Writer {
        file: BufWriter::new(file),
        seq,
        prev_hash,
    })
}

impl AuditLog {
    pub fn open(config: &crate::config::AuditConfig, stderr: bool) -> Result<Self> {
        let (events, _) = broadcast::channel(512);

        Ok(AuditLog {
            inner: Mutex::new(open_chain(config)?),
            events,
            settings: RwLock::new(Settings::from(config)),
            stderr,
        })
    }

    /// Adopt an edited `[audit]` section without restarting.
    ///
    /// A changed `path` is the interesting case: the old file is flushed and
    /// closed, and the new one picks up *its* chain rather than continuing the
    /// old one — two files sharing a sequence would each look tampered with to
    /// `agent-iap audit verify`, which is the tool that has to stay believable.
    /// A record is never written to both.
    pub fn reopen(&self, config: &crate::config::AuditConfig) -> Result<()> {
        let moving = self.settings.read().path != config.path;
        if !moving {
            *self.settings.write() = Settings::from(config);
            return Ok(());
        }

        let opened = open_chain(config)?;
        // Both under one lock, in this order: a record landing between them
        // would otherwise be written to the old file under the new file's
        // sequence, or to the new file under the old one's.
        let mut writer = self.inner.lock();
        let mut settings = self.settings.write();
        if let Err(error) = writer.file.flush() {
            tracing::error!(?error, "flushing the audit log before moving it");
        }
        *writer = opened;
        *settings = Settings::from(config);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.events.subscribe()
    }

    pub fn log_bodies(&self) -> bool {
        self.settings.read().log_bodies
    }

    pub fn log_mcp_params(&self) -> bool {
        self.settings.read().log_mcp_params
    }

    /// Where records are going right now.
    pub fn path(&self) -> PathBuf {
        self.settings.read().path.clone()
    }

    /// Append a record and return the sequenced event.
    ///
    /// The chain only advances when the line actually reached the file. A failed
    /// write therefore leaves the log verifiable and simply missing that entry —
    /// rather than advancing `seq` past a line that was never written and making
    /// everything after it look tampered with.
    ///
    /// Callers decide what a failure means. On a path that is about to *allow*
    /// something, it should mean refusing: a proxy that cannot record what it
    /// permitted has no business permitting it.
    pub fn write(&self, record: AuditRecord) -> Result<AuditEvent> {
        let mut guard = self.inner.lock();
        let mut event = AuditEvent {
            seq: guard.seq,
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            record,
            prev_hash: guard.prev_hash.clone(),
            hash: String::new(),
        };
        event.hash = event.compute_hash();

        let line = serde_json::to_string(&event).context("serialising an audit event")?;
        writeln!(guard.file, "{line}")
            .and_then(|_| guard.file.flush())
            .inspect_err(|error| tracing::error!(%error, "failed to append to the audit log"))
            .context("appending to the audit log")?;

        guard.seq += 1;
        guard.prev_hash = event.hash.clone();
        drop(guard);

        if self.stderr {
            tracing::info!("{}", event.oneline());
        }
        let _ = self.events.send(event.clone());
        Ok(event)
    }

    /// Append a record where the caller has already decided to refuse, or is
    /// past the point of being able to. Denials and shutdown notes still belong
    /// in the log, but failing to record one must not turn a `deny` into a 500.
    pub fn write_best_effort(&self, record: AuditRecord) -> Option<AuditEvent> {
        match self.write(record) {
            Ok(event) => Some(event),
            Err(error) => {
                tracing::error!(?error, "an audit record was lost");
                None
            }
        }
    }

    /// Replace credential-bearing header values with `***`.
    pub fn redact_headers(&self, headers: &http::HeaderMap) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (name, value) in headers {
            let key = name.as_str().to_ascii_lowercase();
            let rendered = if self.settings.read().redact.contains(&key) {
                "***".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            map.insert(key, serde_json::Value::String(rendered));
        }
        serde_json::Value::Object(map)
    }

    /// Truncate a body to the configured cap, marking that it was cut.
    pub fn clip_body(&self, body: &[u8]) -> serde_json::Value {
        let text = String::from_utf8_lossy(body);
        let max_logged_body_bytes = self.settings.read().max_logged_body_bytes;
        if text.len() <= max_logged_body_bytes {
            serde_json::Value::String(text.into_owned())
        } else {
            let mut end = max_logged_body_bytes;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            serde_json::Value::String(format!(
                "{}… <truncated, {} bytes total>",
                &text[..end],
                body.len()
            ))
        }
    }
}

fn read_tail(path: &Path) -> Result<Option<AuditEvent>> {
    if !path.exists() {
        return Ok(None);
    }
    let file =
        File::open(path).with_context(|| format!("opening audit log `{}`", path.display()))?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(
            serde_json::from_str::<AuditEvent>(&line)
                .with_context(|| format!("parsing existing audit log `{}`", path.display()))?,
        );
    }
    Ok(last)
}

/// Identity of the file behind a path, so a rotation is noticed even when the
/// replacement has already grown past where the follower was reading.
#[cfg_attr(not(unix), allow(unused_variables))]
fn file_id(meta: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.ino())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What one read off the end of the log produced.
pub struct Batch {
    /// Complete lines, in order. A half-written line is held back until its
    /// newline arrives, so a follower never shows a truncated record as if the
    /// proxy had written one.
    pub lines: Vec<String>,
    /// The file was truncated or replaced and reading restarted at its
    /// beginning — the lines above come from the new file, not the old one.
    pub rotated: bool,
}

/// An incremental reader over an audit log.
///
/// The proxy appends one flushed line at a time, so following the log is a
/// matter of re-reading whatever landed after the last complete line. Rotation
/// is the case worth care: the file behind the path can be replaced or
/// truncated underneath a reader, and a follower still holding the old handle
/// would go quiet for the rest of its life rather than say so.
pub struct Tail {
    path: PathBuf,
    file: Option<File>,
    id: Option<u64>,
    /// Bytes consumed from the file currently open, for spotting a truncation.
    offset: u64,
    /// A trailing line that has not had its newline yet.
    partial: Vec<u8>,
}

impl Tail {
    /// Start reading `path` from its beginning.
    ///
    /// A log that does not exist yet is not an error: a follower is often
    /// started before the proxy that writes to it, and `read` picks the file up
    /// when it appears.
    pub fn open(path: &Path) -> Result<Self> {
        let mut tail = Tail {
            path: path.to_path_buf(),
            file: None,
            id: None,
            offset: 0,
            partial: Vec::new(),
        };
        tail.reopen()?;
        Ok(tail)
    }

    /// Whether a file is currently open — false while waiting for one to appear.
    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }

    /// `true` if a file was opened, `false` if the path is still empty of one.
    fn reopen(&mut self) -> Result<bool> {
        self.file = None;
        self.id = None;
        self.offset = 0;
        self.partial.clear();

        match File::open(&self.path) {
            Ok(file) => {
                self.id = file.metadata().ok().as_ref().and_then(file_id);
                self.file = Some(file);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("opening audit log `{}`", self.path.display()))
            }
        }
    }

    /// Every complete line appended since the last call.
    pub fn read(&mut self) -> Result<Batch> {
        let mut rotated = false;

        match std::fs::metadata(&self.path) {
            Ok(meta) => {
                // A handle survives the rename that logrotate does, so the
                // check has to be against the path, not against what is open.
                let replaced = file_id(&meta) != self.id || meta.len() < self.offset;
                if self.file.is_none() || replaced {
                    let had_file = self.file.is_some();
                    rotated = self.reopen()? && had_file;
                }
            }
            // Renamed away and not yet replaced. Keep the old handle: whatever
            // is still being appended to it is still the log, and the new file
            // is picked up on a later read.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("reading `{}`", self.path.display()))
            }
        }

        let mut lines = Vec::new();
        if let Some(file) = self.file.as_mut() {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)
                .with_context(|| format!("reading `{}`", self.path.display()))?;
            self.offset += buffer.len() as u64;
            self.partial.extend_from_slice(&buffer);

            while let Some(index) = self.partial.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.partial.drain(..=index).collect();
                let line = String::from_utf8_lossy(&line[..index]);
                lines.push(line.trim_end_matches('\r').to_string());
            }
        }

        Ok(Batch { lines, rotated })
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
}

/// Walk the chain and prove nothing was edited, reordered or removed.
pub fn verify_file(path: &Path) -> Result<VerifyReport> {
    let file =
        File::open(path).with_context(|| format!("opening audit log `{}`", path.display()))?;

    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut entries = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;

    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let line_no = index + 1;
        let event: AuditEvent = serde_json::from_str(&line)
            .with_context(|| format!("line {line_no} is not a valid audit event"))?;

        if event.seq != expected_seq {
            bail!(
                "line {line_no}: sequence gap — expected seq {expected_seq}, found {}",
                event.seq
            );
        }
        if event.prev_hash != expected_prev {
            bail!("line {line_no}: chain break — prev_hash does not match the previous entry");
        }
        if event.compute_hash() != event.hash {
            bail!("line {line_no}: entry was modified after it was written");
        }

        if first_ts.is_none() {
            first_ts = Some(event.ts.clone());
        }
        last_ts = Some(event.ts.clone());
        expected_prev = event.hash;
        expected_seq += 1;
        entries += 1;
    }

    Ok(VerifyReport {
        entries,
        first_ts,
        last_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;

    fn log_in(dir: &Path) -> (AuditLog, std::path::PathBuf) {
        let path = dir.join("audit.jsonl");
        let config = AuditConfig {
            path: path.clone(),
            stderr: false,
            ..Default::default()
        };
        (AuditLog::open(&config, false).unwrap(), path)
    }

    fn entry_for(agent: &str, target: &str) -> AuditEvent {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        let mut record = AuditRecord::new("http", "request");
        record.agent = agent.to_string();
        record.target = target.to_string();
        log.write(record).unwrap();
        drop(log);
        let line = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }

    #[test]
    fn a_filtered_view_narrows_one_shared_log_to_one_agent() {
        let entry = entry_for("bravo", "github");

        assert!(entry.matches(None, None));
        assert!(entry.matches(Some("bravo"), None));
        assert!(entry.matches(None, Some("github")));
        assert!(entry.matches(Some("bravo"), Some("github")));

        // Both filters are conjunctive: the right agent against the wrong
        // target is not a hit, which is what makes the view trustworthy when
        // several agents share one upstream.
        assert!(!entry.matches(Some("alpha"), None));
        assert!(!entry.matches(None, Some("anthropic")));
        assert!(!entry.matches(Some("bravo"), Some("anthropic")));
        assert!(!entry.matches(Some("alpha"), Some("github")));

        // Exact, not prefix: `ci-1` must never answer for `ci-10`.
        assert!(!entry_for("ci-1", "github").matches(Some("ci-10"), None));
        assert!(!entry_for("ci-10", "github").matches(Some("ci-1"), None));
    }

    #[test]
    fn chain_verifies_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        for index in 0..3 {
            let mut record = AuditRecord::new("http", "request");
            record.agent = format!("agent-{index}");
            log.write(record).unwrap();
        }
        drop(log);

        assert_eq!(verify_file(&path).unwrap().entries, 3);

        // Reopening must continue the chain rather than restart it.
        let (log, _) = log_in(dir.path());
        log.write(AuditRecord::new("mcp", "request")).unwrap();
        drop(log);
        assert_eq!(verify_file(&path).unwrap().entries, 4);
    }

    #[test]
    fn an_edited_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        let mut record = AuditRecord::new("http", "request");
        record.decision = Some("deny".into());
        log.write(record).unwrap();
        log.write(AuditRecord::new("http", "request")).unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"deny\"", "\"allow\"")).unwrap();

        let err = verify_file(&path).unwrap_err().to_string();
        assert!(err.contains("modified after it was written"), "{err}");
    }

    #[test]
    fn a_removed_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        for _ in 0..3 {
            log.write(AuditRecord::new("http", "request")).unwrap();
        }
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n")).unwrap();

        let err = verify_file(&path).unwrap_err().to_string();
        assert!(err.contains("sequence gap"), "{err}");
    }

    #[test]
    fn a_failed_write_does_not_advance_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        log.write(AuditRecord::new("http", "request")).unwrap();

        // Make the next append fail the way a full or read-only disk would.
        {
            let mut guard = log.inner.lock();
            guard.file = BufWriter::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(dir.path().join("audit.jsonl"))
                    .unwrap(),
            );
        }
        assert!(
            log.write(AuditRecord::new("http", "request")).is_err(),
            "an unwritable log must report failure, not swallow it"
        );

        // Restore a working handle and carry on.
        {
            let mut guard = log.inner.lock();
            guard.file = BufWriter::new(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
            );
        }
        log.write(AuditRecord::new("http", "request")).unwrap();
        drop(log);

        // Two entries reached the file, and the chain over them is intact — the
        // lost record must not leave a gap that reads as tampering.
        let report = verify_file(&path).unwrap();
        assert_eq!(report.entries, 2);
    }

    #[test]
    fn credential_headers_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let (log, _) = log_in(dir.path());
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer sk-secret".parse().unwrap());
        headers.insert("x-api-key", "sk-ant-secret".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let rendered = log.redact_headers(&headers).to_string();
        assert!(!rendered.contains("sk-secret"), "{rendered}");
        assert!(!rendered.contains("sk-ant-secret"), "{rendered}");
        assert!(rendered.contains("application/json"));
    }

    #[test]
    fn bodies_are_clipped_on_a_char_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(
            &AuditConfig {
                path: dir.path().join("audit.jsonl"),
                stderr: false,
                max_logged_body_bytes: 5,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        let clipped = log.clip_body("aaaaübbbb".as_bytes()).to_string();
        assert!(clipped.contains("truncated"), "{clipped}");
    }

    #[test]
    fn a_follower_sees_what_is_appended_after_it_started() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        log.write(AuditRecord::new("http", "request")).unwrap();

        let mut tail = Tail::open(&path).unwrap();
        assert_eq!(tail.read().unwrap().lines.len(), 1);
        // Nothing new is not an error and not a repeat of what was already read.
        assert!(tail.read().unwrap().lines.is_empty());

        log.write(AuditRecord::new("http", "denied")).unwrap();
        let batch = tail.read().unwrap();
        assert_eq!(batch.lines.len(), 1, "the new entry, and only it");
        assert!(batch.lines[0].contains("denied"), "{:?}", batch.lines);
        assert!(!batch.rotated);
    }

    #[test]
    fn a_half_written_line_is_held_back_until_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"{\"seq\":0,").unwrap();

        let mut tail = Tail::open(&path).unwrap();
        assert!(
            tail.read().unwrap().lines.is_empty(),
            "half a record must not be shown as if the proxy had written it"
        );

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"\"rest\":1}\n").unwrap();
        assert_eq!(tail.read().unwrap().lines, vec!["{\"seq\":0,\"rest\":1}"]);
    }

    #[test]
    fn a_rotated_log_is_followed_to_the_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "first\n").unwrap();

        let mut tail = Tail::open(&path).unwrap();
        assert_eq!(tail.read().unwrap().lines, vec!["first"]);

        // What logrotate does: rename the file away, then create a new one. The
        // follower's handle survives the rename, so without noticing the swap it
        // would sit on the old inode and never print another line.
        std::fs::rename(&path, dir.path().join("audit.jsonl.1")).unwrap();
        std::fs::write(&path, "second\n").unwrap();

        let batch = tail.read().unwrap();
        assert_eq!(batch.lines, vec!["second"]);
        assert!(
            batch.rotated,
            "the reader is owed the fact that it restarted"
        );
    }

    #[test]
    fn a_truncated_log_is_re_read_from_its_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();

        let mut tail = Tail::open(&path).unwrap();
        assert_eq!(tail.read().unwrap().lines.len(), 3);

        // Truncated in place, which leaves the offset past the end of the file.
        std::fs::write(&path, "fresh\n").unwrap();
        let batch = tail.read().unwrap();
        assert_eq!(batch.lines, vec!["fresh"]);
        assert!(batch.rotated);
    }

    #[test]
    fn a_log_that_does_not_exist_yet_is_waited_for_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // A follower is routinely started before the proxy it is watching.
        let mut tail = Tail::open(&path).unwrap();
        assert!(!tail.is_open());
        assert!(tail.read().unwrap().lines.is_empty());

        let (log, _) = log_in(dir.path());
        log.write(AuditRecord::new("http", "request")).unwrap();

        let batch = tail.read().unwrap();
        assert!(tail.is_open());
        assert_eq!(batch.lines.len(), 1);
    }
}
