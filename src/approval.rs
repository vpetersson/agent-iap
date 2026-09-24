//! Interactive approval — the Little Snitch part.
//!
//! An `ask` verdict parks the request here and blocks it until a human answers
//! in the TUI (or over the control API). Nothing is ever allowed by default:
//! a timeout, or having no approver attached at all, denies.
//!
//! The queue holds questions rather than requests. An agent whose call is
//! parked retries it, and the retries are the same question — see `Pending` —
//! so they wait together and one answer releases all of them.

use indexmap::IndexMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::acl::{AccessRequest, Kind};
use crate::bell::Bell;

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

/// What the TUI and the control API see for one parked question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingView {
    pub id: String,
    pub request: AccessRequest,
    pub summary: String,
    /// How long the oldest request behind this question has waited — the one
    /// closest to timing out.
    pub waited_ms: u64,
    /// How long the newest has. Equal to `waited_ms` until a retry arrives,
    /// and after that the difference between a loop still running and one that
    /// gave up while the queue waited on a human.
    #[serde(default)]
    pub newest_ms: u64,
    /// How many identical requests one answer here releases. `1` normally;
    /// more whenever an agent retried a call that was already parked.
    #[serde(default = "one")]
    pub waiting: usize,
    pub agent_name: String,
    /// The `ask` rule that parked it, when a rule did rather than the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_by: Option<AskingRule>,
}

fn one() -> usize {
    1
}

/// One question, and every request waiting on the answer to it.
///
/// An agent that is kept waiting does not sit and think: it retries, and each
/// retry parks a request of its own. Six of those are not six questions. The
/// ACL cannot tell them apart — it decides on agent, kind, target, method and
/// path, and so does every `Scope` an answer can be given at — so there is
/// nothing an operator could say about one that would not be equally true of
/// the next, and a console that lists them separately asks the same question
/// six times and frees one request per answer. They are parked together
/// instead: one row, one answer, every waiter released by it.
///
/// What this deliberately does not look at is the body. Nothing in this proxy
/// decides on a body — not a rule, not a scope, not a remembered answer — so
/// two `POST /v1/tts` calls carrying different text are already one question
/// everywhere else, and collapsing them here grants nothing that answering the
/// first of them did not already grant.
struct Pending {
    /// What makes two requests the same question: `session_key`, the same
    /// string "remember for this session" has always been keyed by.
    key: String,
    request: AccessRequest,
    agent_name: String,
    asked_by: Option<AskingRule>,
    /// When the first of these parked. The queue is oldest-first and the row
    /// reports this one, because it is the deadline that runs out first.
    created: Instant,
    /// When the most recent one did.
    latest: Instant,
    /// Everyone waiting on this answer, in arrival order. Keyed by a ticket so
    /// a caller that goes away takes only its own place in the queue with it.
    waiters: IndexMap<u64, oneshot::Sender<Verdict>>,
    next_ticket: u64,
}

/// One caller's place in a parked question, given up when its request goes away.
///
/// Held by the `ask` future and dropped with it, so a caller leaves the queue
/// whether it was answered, timed out, or cancelled part-way through because
/// the agent hung up. Without the last of those the row goes on counting a
/// request nobody is waiting for — the same wrong number this queue exists to
/// stop showing — and the question outlives every caller that asked it.
struct Ticket<'a> {
    broker: &'a ApprovalBroker,
    id: String,
    ticket: u64,
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        {
            let mut queue = self.broker.pending.lock();
            if let Some(pending) = queue.get_mut(&self.id) {
                pending.waiters.shift_remove(&self.ticket);
                if pending.waiters.is_empty() {
                    queue.shift_remove(&self.id);
                }
            }
        }
        let _ = self.broker.changes.send(());
    }
}

/// How long a control-plane poll counts as someone still watching the queue.
/// Long enough for a human tailing it with `curl`, short enough that a
/// forgotten shell does not keep requests parked for the full timeout.
const APPROVER_POLL_TTL: Duration = Duration::from_secs(30);

pub struct ApprovalBroker {
    /// The questions waiting for a human, oldest first — one entry per
    /// distinct request, however many copies of it are parked behind it.
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
    /// Rung when a request parks. Here rather than in the console because
    /// this is the one place that knows a request stopped on a human, and it
    /// is the same place whether the console or the control plane is the
    /// thing that will answer it.
    bell: Bell,
}

impl ApprovalBroker {
    pub fn new(timeout: Duration, bell: bool) -> Self {
        let (changes, _) = broadcast::channel(64);
        ApprovalBroker {
            pending: Mutex::new(IndexMap::new()),
            remembered: Mutex::new(Vec::new()),
            console_attached: AtomicBool::new(false),
            last_poll: Mutex::new(None),
            changes,
            timeout: Mutex::new(timeout),
            bell: Bell::new(bell),
        }
    }

    /// Adopt an edited `approval_timeout_secs`. Requests already parked keep
    /// the deadline they were parked with — a timeout that moves under a
    /// request in flight is a request nobody can reason about.
    pub fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock() = timeout;
    }

    /// Adopt an edited `approval_bell`, so an operator who finds out they
    /// wanted it — which is, reliably, just after a request timed out
    /// unnoticed — gets it without restarting the proxy.
    pub fn set_bell(&self, on: bool) {
        self.bell.set_enabled(on);
    }

    pub fn bell_enabled(&self) -> bool {
        self.bell.enabled()
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

        let (responder, receiver) = oneshot::channel();
        let (_ticket, is_new) = self.park(request, agent_name, asked_by, responder);
        let _ = self.changes.send(());
        // Only now: everything above is a reason the request never reached a
        // human, and a bell for a question nobody was going to be asked is
        // the noise that gets the bell turned off. A retry joining a row that
        // is already on screen is not news either, and is not rung for. The
        // outcome is dropped on purpose — a request must never be held up, let
        // alone refused, because a terminal would not take a byte.
        if is_new {
            self.bell.ring();
        }

        let timeout = *self.timeout.lock();
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(verdict)) => Outcome::Decided(verdict),
            // Sender dropped: the queue was cleared out from under us. Fail closed.
            Ok(Err(_)) => Outcome::TimedOut,
            Err(_) => Outcome::TimedOut,
        }
        // `_ticket` drops here — or wherever this future was cancelled — and
        // that, rather than anything on the way out, is what takes this caller
        // out of the queue.
    }

    /// Join the question this request asks, raising it if it is not already up.
    ///
    /// Returns the caller's place in it and whether the question is new — the
    /// one thing above that a retry has to be told apart from a first attempt.
    fn park(
        &self,
        request: &AccessRequest,
        agent_name: &str,
        asked_by: Option<AskingRule>,
        responder: oneshot::Sender<Verdict>,
    ) -> (Ticket<'_>, bool) {
        let key = request.session_key();
        let mut queue = self.pending.lock();
        let asked_already = queue
            .iter()
            .find(|(_, pending)| pending.key == key)
            .map(|(id, _)| id.clone());

        if let Some(id) = asked_already {
            let pending = queue.get_mut(&id).expect("just found under this key");
            let ticket = pending.next_ticket;
            pending.next_ticket += 1;
            pending.latest = Instant::now();
            pending.waiters.insert(ticket, responder);
            return (
                Ticket {
                    broker: self,
                    id,
                    ticket,
                },
                false,
            );
        }

        let id = Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut waiters = IndexMap::new();
        waiters.insert(0, responder);
        queue.insert(
            id.clone(),
            Pending {
                key,
                request: request.clone(),
                agent_name: agent_name.to_string(),
                asked_by,
                created: now,
                latest: now,
                waiters,
                next_ticket: 1,
            },
        );
        (
            Ticket {
                broker: self,
                id,
                ticket: 0,
            },
            true,
        )
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
                newest_ms: pending.latest.elapsed().as_millis() as u64,
                waiting: pending.waiters.len(),
                agent_name: pending.agent_name.clone(),
                asked_by: pending.asked_by.clone(),
            })
            .collect()
    }

    /// Questions waiting for an answer — rows in the console, not requests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Requests waiting, which is the larger number whenever an agent is
    /// retrying one. Every one of them is released by the single answer given
    /// to the question it is parked under.
    pub fn waiting_count(&self) -> usize {
        self.pending
            .lock()
            .values()
            .map(|pending| pending.waiters.len())
            .sum()
    }

    /// Answer one parked question. `remember` applies the same answer to
    /// identical requests for as long as this process runs.
    pub fn decide(&self, id: &str, verdict: Verdict, remember: bool) -> bool {
        let scope = if remember {
            match self.pending.lock().get(id) {
                Some(pending) => Some(Scope::exact(&pending.request)),
                // Nothing to answer and so nothing to stand by: an answer to a
                // question that is no longer being asked is not an intent about
                // anything, and this one was only ever "this exact call again".
                None => return false,
            }
        } else {
            None
        };
        self.decide_scoped(id, verdict, scope)
    }

    /// Answer one parked question, and stand by that answer for everything
    /// `scope` covers until this process exits.
    ///
    /// The standing answer is recorded whether or not the question that
    /// prompted it is still up: it is the operator's intent about a whole class
    /// of calls, not about the one that happened to raise the dialogue, and
    /// that one may well have timed out while they read it.
    pub fn decide_scoped(&self, id: &str, verdict: Verdict, scope: Option<Scope>) -> bool {
        let named = self.pending.lock().shift_remove(id);
        let mut covered = Vec::new();
        if let Some(scope) = scope {
            self.remember(scope.clone(), verdict);
            // The standing answer answers what is already parked, too. Those
            // requests would have been short-circuited on arrival by
            // `remembered_verdict` had they come in a second later; left in the
            // queue they sit out the timeout and are denied, which is the
            // opposite of what was just said about them, and nothing will
            // raise them again for the operator to notice.
            covered = self.take_covered(&scope);
        }
        let delivered = match named {
            Some(pending) => self.deliver(pending, verdict),
            None => false,
        };
        for pending in covered {
            self.deliver(pending, verdict);
        }
        delivered
    }

    /// Take every question a standing answer has just settled out of the queue.
    fn take_covered(&self, scope: &Scope) -> Vec<Pending> {
        let mut queue = self.pending.lock();
        let ids: Vec<String> = queue
            .iter()
            .filter(|(_, pending)| scope.matches(&pending.request))
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter_map(|id| queue.shift_remove(id)).collect()
    }

    /// Hand one answer to everyone who was waiting on it.
    fn deliver(&self, pending: Pending, verdict: Verdict) -> bool {
        let mut delivered = false;
        for responder in pending.waiters.into_values() {
            // False for a caller that gave up before the answer arrived. The
            // rest still get theirs — one agent hanging up is not a reason to
            // keep the others waiting for a timeout.
            delivered |= responder.send(verdict).is_ok();
        }
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
        let broker = ApprovalBroker::new(Duration::from_secs(5), false);
        let outcome = broker.ask(&request(), "Claude", None).await;
        assert_eq!(outcome, Outcome::NoApprover);
        assert_eq!(outcome.verdict(), Verdict::Deny);
    }

    #[tokio::test]
    async fn polling_the_queue_counts_as_watching_it_for_a_while() {
        let broker = ApprovalBroker::new(Duration::from_secs(5), false);
        assert!(!broker.has_approver());
        broker.note_poll();
        assert!(
            broker.has_approver(),
            "a fresh poll means someone can answer"
        );
    }

    #[tokio::test]
    async fn a_human_allow_releases_the_request() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
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
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
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

    /// Waits until the queue holds `questions` rows, or gives up.
    async fn queue_of(broker: &ApprovalBroker, questions: usize) -> Vec<PendingView> {
        for _ in 0..400 {
            let queue = broker.list();
            if queue.len() == questions && queue.iter().all(|view| view.waiting > 0) {
                return queue;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the queue never reached {questions} question(s)");
    }

    fn asking(
        broker: &Arc<ApprovalBroker>,
        request: AccessRequest,
    ) -> tokio::task::JoinHandle<Outcome> {
        let broker = Arc::clone(broker);
        tokio::spawn(async move { broker.ask(&request, "Claude", None).await })
    }

    /// The reported pile: an agent retries a parked call, and the console fills
    /// with the same row over and over. They are one question, and one answer
    /// has to release every request behind it — otherwise the operator answers
    /// six times and five of the six calls time out denied in between.
    #[tokio::test]
    async fn a_retried_request_is_one_question_and_one_answer_frees_all_of_it() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
        broker.set_has_approver(true);

        let askers: Vec<_> = (0..6).map(|_| asking(&broker, request())).collect();
        let queue = queue_of(&broker, 1).await;

        assert_eq!(queue.len(), 1, "six identical calls are one question");
        assert_eq!(queue[0].waiting, 6, "and it says how many are behind it");
        assert_eq!(broker.pending_count(), 1);
        assert_eq!(broker.waiting_count(), 6);

        assert!(broker.decide(&queue[0].id, Verdict::Allow, false));
        for asker in askers {
            assert_eq!(asker.await.unwrap(), Outcome::Decided(Verdict::Allow));
        }
        assert_eq!(
            broker.pending_count(),
            0,
            "and the queue is empty after one"
        );
    }

    /// Only *identical* calls collapse. A different path is a different
    /// decision and still has to be put to a human on its own.
    #[tokio::test]
    async fn a_different_call_is_still_a_question_of_its_own() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
        broker.set_has_approver(true);

        let one = asking(&broker, request());
        let two = asking(&broker, request());
        let other = asking(
            &broker,
            AccessRequest::http("claude", "gh", "DELETE", "/repos/x"),
        );

        let queue = queue_of(&broker, 2).await;
        assert_eq!(queue[0].waiting, 2);
        assert_eq!(queue[1].waiting, 1);
        assert_eq!(queue[1].request.method, "DELETE");

        broker.decide(&queue[0].id, Verdict::Allow, false);
        assert_eq!(one.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(two.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(
            broker.pending_count(),
            1,
            "the DELETE was never answered and is still waiting"
        );
        broker.decide(&queue[1].id, Verdict::Deny, false);
        assert_eq!(other.await.unwrap(), Outcome::Decided(Verdict::Deny));
    }

    /// A standing answer settles what is already parked, too. These requests
    /// would have been short-circuited on arrival had they come in a moment
    /// later; leaving them to time out denies calls the operator just allowed.
    #[tokio::test]
    async fn a_standing_answer_releases_what_is_already_waiting() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
        broker.set_has_approver(true);

        let asked = asking(&broker, request());
        let elsewhere = asking(
            &broker,
            AccessRequest::http("claude", "gh", "DELETE", "/repos/x"),
        );
        let other_service = asking(
            &broker,
            AccessRequest::http("claude", "sentry", "GET", "/x"),
        );
        let queue = queue_of(&broker, 3).await;

        // "anything this agent does to gh", the dialogue's widest row.
        let anything_on_gh = Scope {
            agent: Some("claude".into()),
            kind: Some(Kind::Http),
            target: Some("gh".into()),
            ..Scope::default()
        };
        assert!(broker.decide_scoped(&queue[0].id, Verdict::Allow, Some(anything_on_gh)));

        assert_eq!(asked.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(
            elsewhere.await.unwrap(),
            Outcome::Decided(Verdict::Allow),
            "the DELETE the standing answer covers goes out with it"
        );
        assert_eq!(
            broker.pending_count(),
            1,
            "and nothing the answer did not cover was touched"
        );
        broker.decide(&queue[2].id, Verdict::Deny, false);
        assert_eq!(
            other_service.await.unwrap(),
            Outcome::Decided(Verdict::Deny)
        );
    }

    /// A caller that hangs up takes its own place in the queue and nothing
    /// else. A row that goes on counting a request nobody is waiting for is
    /// the same wrong number, arrived at from the other side.
    #[tokio::test]
    async fn a_caller_that_gives_up_leaves_the_others_waiting() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
        broker.set_has_approver(true);

        let stays = asking(&broker, request());
        let goes = asking(&broker, request());
        assert_eq!(queue_of(&broker, 1).await[0].waiting, 2);

        goes.abort();
        for _ in 0..400 {
            if broker.waiting_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let queue = broker.list();
        assert_eq!(queue.len(), 1, "the question is still being asked");
        assert_eq!(queue[0].waiting, 1, "by the one caller still waiting on it");

        broker.decide(&queue[0].id, Verdict::Allow, false);
        assert_eq!(stays.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(broker.pending_count(), 0);
    }

    /// And the last one leaving empties the queue rather than leaving a row
    /// with nobody behind it.
    #[tokio::test]
    async fn the_question_goes_when_the_last_caller_does() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5), false));
        broker.set_has_approver(true);

        let only = asking(&broker, request());
        queue_of(&broker, 1).await;
        only.abort();

        for _ in 0..400 {
            if broker.pending_count() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("a request nobody is waiting for is still in the queue");
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out_denied() {
        let broker = ApprovalBroker::new(Duration::from_millis(40), false);
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
