//! Interactive approval — the Little Snitch part.
//!
//! An `ask` verdict parks the request here and blocks it until a human answers
//! in the TUI (or over the control API). Nothing is ever allowed by default:
//! a timeout, or having no approver attached at all, denies.

use indexmap::IndexMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::acl::{AccessRequest, Kind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// How a parked request was ultimately resolved — recorded verbatim in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A human answered.
    Decided(Verdict),
    /// A "remember for this session" answer given earlier applied.
    Remembered(Verdict),
    /// Nobody answered in time.
    TimedOut,
    /// Nothing is watching the queue, so there is no one to answer.
    NoApprover,
}

impl Outcome {
    pub fn verdict(self) -> Verdict {
        match self {
            Outcome::Decided(v) | Outcome::Remembered(v) => v,
            // Fail closed.
            Outcome::TimedOut | Outcome::NoApprover => Verdict::Deny,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Decided(Verdict::Allow) => "ask:allowed",
            Outcome::Decided(Verdict::Deny) => "ask:denied",
            Outcome::Remembered(Verdict::Allow) => "ask:allowed-remembered",
            Outcome::Remembered(Verdict::Deny) => "ask:denied-remembered",
            Outcome::TimedOut => "ask:timeout-denied",
            Outcome::NoApprover => "ask:no-approver-denied",
        }
    }
}

/// How wide an answer reaches.
///
/// The Little Snitch dialogue's second column: an operator allowing one call is
/// answering a different question from one allowing everything this agent ever
/// does to this service, and a console that can only express the narrowest of
/// them trains its operator to hold the key down.
///
/// A `None` field places no constraint. Matching is exact rather than glob:
/// every scope here is built from a request that actually arrived, so there is
/// nothing to pattern-match and nothing for a stray `*` in a tool name to do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub agent: Option<String>,
    pub kind: Option<Kind>,
    pub target: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
}

impl Scope {
    /// This request and nothing else — what `remember` meant before scopes.
    pub fn exact(request: &AccessRequest) -> Self {
        Scope {
            agent: Some(request.agent.clone()),
            kind: Some(request.kind),
            target: Some(request.target.clone()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
        }
    }

    pub fn matches(&self, request: &AccessRequest) -> bool {
        self.agent.as_ref().is_none_or(|a| *a == request.agent)
            && self.kind.is_none_or(|k| k == request.kind)
            && self.target.as_ref().is_none_or(|t| *t == request.target)
            && self.method.as_ref().is_none_or(|m| *m == request.method)
            && self.path.as_ref().is_none_or(|p| *p == request.path)
    }
}

/// The rule that sent this request to a human.
///
/// Carried through to the console because an answer meant to hold *from now on*
/// has to be written into the file in front of this position — appended after
/// it, a new `allow` would sit behind the `ask` that is still matching first,
/// and the operator would be asked the same question forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskingRule {
    pub index: usize,
    pub label: String,
}

impl AskingRule {
    /// The rule an `ask` decision came from.
    ///
    /// `None` when the *default* did the asking: there is no rule to write in
    /// front of, so a standing answer appends to the end of the list instead.
    pub fn of(decision: &crate::acl::Decision) -> Option<Self> {
        Some(AskingRule {
            index: decision.index?,
            label: decision.rule.clone()?,
        })
    }
}

/// What the TUI and the control API see for one parked request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingView {
    pub id: String,
    pub request: AccessRequest,
    pub summary: String,
    pub waited_ms: u64,
    pub agent_name: String,
    /// The `ask` rule that parked it, when a rule did rather than the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_by: Option<AskingRule>,
}

struct Pending {
    request: AccessRequest,
    agent_name: String,
    asked_by: Option<AskingRule>,
    created: Instant,
    responder: oneshot::Sender<Verdict>,
}

/// How long a control-plane poll counts as someone still watching the queue.
/// Long enough for a human tailing it with `curl`, short enough that a
/// forgotten shell does not keep requests parked for the full timeout.
const APPROVER_POLL_TTL: Duration = Duration::from_secs(30);

pub struct ApprovalBroker {
    pending: Mutex<IndexMap<String, Pending>>,
    /// "…and remember for this session" answers. Newest first, because an
    /// operator who narrows or reverses an earlier standing answer means the
    /// new one — the alternative is a decision that cannot be taken back
    /// without restarting the proxy.
    remembered: Mutex<Vec<(Scope, Verdict)>>,
    console_attached: AtomicBool,
    last_poll: Mutex<Option<Instant>>,
    changes: broadcast::Sender<()>,
    /// How long a parked request waits. Editable while running, because the
    /// operator who discovers it is too short is the one currently watching a
    /// request time out.
    timeout: Mutex<Duration>,
}

impl ApprovalBroker {
    pub fn new(timeout: Duration) -> Self {
        let (changes, _) = broadcast::channel(64);
        ApprovalBroker {
            pending: Mutex::new(IndexMap::new()),
            remembered: Mutex::new(Vec::new()),
            console_attached: AtomicBool::new(false),
            last_poll: Mutex::new(None),
            changes,
            timeout: Mutex::new(timeout),
        }
    }

    /// Adopt an edited `approval_timeout_secs`. Requests already parked keep
    /// the deadline they were parked with — a timeout that moves under a
    /// request in flight is a request nobody can reason about.
    pub fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock() = timeout;
    }

    /// Declare that the interactive console is running.
    pub fn set_has_approver(&self, value: bool) {
        self.console_attached.store(value, Ordering::SeqCst);
    }

    /// Someone read the queue over the control plane; they can answer for a while.
    pub fn note_poll(&self) {
        *self.last_poll.lock() = Some(Instant::now());
    }

    /// Is anyone actually in a position to answer? If not, `ask` must not park a
    /// request for the full timeout — it should deny immediately.
    pub fn has_approver(&self) -> bool {
        self.console_attached.load(Ordering::SeqCst)
            || self
                .last_poll
                .lock()
                .is_some_and(|at| at.elapsed() < APPROVER_POLL_TTL)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.changes.subscribe()
    }

    /// Park a request until a human answers, a remembered answer applies, or we time out.
    pub async fn ask(
        &self,
        request: &AccessRequest,
        agent_name: &str,
        asked_by: Option<AskingRule>,
    ) -> Outcome {
        if let Some(verdict) = self.remembered_verdict(request) {
            return Outcome::Remembered(verdict);
        }
        if !self.has_approver() {
            return Outcome::NoApprover;
        }

        let id = Uuid::new_v4().to_string();
        let (responder, receiver) = oneshot::channel();
        self.pending.lock().insert(
            id.clone(),
            Pending {
                request: request.clone(),
                agent_name: agent_name.to_string(),
                asked_by,
                created: Instant::now(),
                responder,
            },
        );
        let _ = self.changes.send(());

        let timeout = *self.timeout.lock();
        let outcome = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(verdict)) => Outcome::Decided(verdict),
            // Sender dropped: the queue was cleared out from under us. Fail closed.
            Ok(Err(_)) => Outcome::TimedOut,
            Err(_) => Outcome::TimedOut,
        };

        self.pending.lock().shift_remove(&id);
        let _ = self.changes.send(());
        outcome
    }

    pub fn list(&self) -> Vec<PendingView> {
        let guard = self.pending.lock();
        guard
            .iter()
            .map(|(id, pending)| PendingView {
                id: id.clone(),
                summary: pending.request.summary(),
                request: pending.request.clone(),
                waited_ms: pending.created.elapsed().as_millis() as u64,
                agent_name: pending.agent_name.clone(),
                asked_by: pending.asked_by.clone(),
            })
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Answer one parked request. `remember` applies the same answer to identical
    /// requests for as long as this process runs.
    pub fn decide(&self, id: &str, verdict: Verdict, remember: bool) -> bool {
        let Some(pending) = self.pending.lock().shift_remove(id) else {
            return false;
        };
        if remember {
            self.remember(Scope::exact(&pending.request), verdict);
        }
        self.deliver(pending, verdict)
    }

    /// Answer one parked request, and stand by that answer for everything
    /// `scope` covers until this process exits.
    ///
    /// The standing answer is recorded first, and whether or not the request
    /// that prompted it is still parked: it is the operator's intent about a
    /// whole class of calls, not about the one that happened to raise the
    /// dialogue, and that one may well have timed out while they read it.
    pub fn decide_scoped(&self, id: &str, verdict: Verdict, scope: Option<Scope>) -> bool {
        if let Some(scope) = scope {
            self.remember(scope, verdict);
        }
        let Some(pending) = self.pending.lock().shift_remove(id) else {
            return false;
        };
        self.deliver(pending, verdict)
    }

    fn deliver(&self, pending: Pending, verdict: Verdict) -> bool {
        let delivered = pending.responder.send(verdict).is_ok();
        let _ = self.changes.send(());
        delivered
    }

    /// Stand by `verdict` for everything `scope` covers, from now until exit.
    pub fn remember(&self, scope: Scope, verdict: Verdict) {
        self.remembered.lock().push((scope, verdict));
        let _ = self.changes.send(());
    }

    /// The standing answer that covers this request, newest first.
    fn remembered_verdict(&self, request: &AccessRequest) -> Option<Verdict> {
        self.remembered
            .lock()
            .iter()
            .rev()
            .find(|(scope, _)| scope.matches(request))
            .map(|(_, verdict)| *verdict)
    }

    /// The standing answers, newest first — what the console lists so an
    /// operator can see what they have already waved through.
    pub fn remembered(&self) -> Vec<(Scope, Verdict)> {
        let mut answers = self.remembered.lock().clone();
        answers.reverse();
        answers
    }

    /// Answer the request that has been waiting longest — the TUI's default target.
    pub fn decide_first(&self, verdict: Verdict, remember: bool) -> bool {
        let id = self.pending.lock().keys().next().cloned();
        match id {
            Some(id) => self.decide(&id, verdict, remember),
            None => false,
        }
    }

    pub fn remembered_count(&self) -> usize {
        self.remembered.lock().len()
    }

    pub fn forget_all(&self) {
        self.remembered.lock().clear();
        let _ = self.changes.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn request() -> AccessRequest {
        AccessRequest::http("claude", "gh", "POST", "/repos/x/issues")
    }

    #[tokio::test]
    async fn denies_when_nothing_is_watching_the_queue() {
        let broker = ApprovalBroker::new(Duration::from_secs(5));
        let outcome = broker.ask(&request(), "Claude", None).await;
        assert_eq!(outcome, Outcome::NoApprover);
        assert_eq!(outcome.verdict(), Verdict::Deny);
    }

    #[tokio::test]
    async fn polling_the_queue_counts_as_watching_it_for_a_while() {
        let broker = ApprovalBroker::new(Duration::from_secs(5));
        assert!(!broker.has_approver());
        broker.note_poll();
        assert!(
            broker.has_approver(),
            "a fresh poll means someone can answer"
        );
    }

    #[tokio::test]
    async fn a_human_allow_releases_the_request() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5)));
        broker.set_has_approver(true);

        let asker = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.ask(&request(), "Claude", None).await })
        };

        // Wait for it to appear in the queue, then answer it.
        let id = loop {
            if let Some(view) = broker.list().into_iter().next() {
                break view.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert!(broker.decide(&id, Verdict::Allow, false));

        assert_eq!(asker.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(broker.pending_count(), 0);
    }

    #[tokio::test]
    async fn remembering_short_circuits_the_next_identical_request() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5)));
        broker.set_has_approver(true);

        let asker = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.ask(&request(), "Claude", None).await })
        };
        let id = loop {
            if let Some(view) = broker.list().into_iter().next() {
                break view.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        broker.decide(&id, Verdict::Allow, true);
        asker.await.unwrap();

        // Same request again: answered from memory, without parking.
        assert_eq!(
            broker.ask(&request(), "Claude", None).await,
            Outcome::Remembered(Verdict::Allow)
        );
        // A different path is a different decision and must be asked again.
        let other = AccessRequest::http("claude", "gh", "DELETE", "/repos/x");
        broker.set_has_approver(false);
        assert_eq!(
            broker.ask(&other, "Claude", None).await,
            Outcome::NoApprover
        );

        broker.forget_all();
        assert_eq!(broker.remembered_count(), 0);
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out_denied() {
        let broker = ApprovalBroker::new(Duration::from_millis(40));
        broker.set_has_approver(true);
        let outcome = broker.ask(&request(), "Claude", None).await;
        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(outcome.verdict(), Verdict::Deny);
        assert_eq!(
            broker.pending_count(),
            0,
            "timed-out requests must be reaped"
        );
    }
}
