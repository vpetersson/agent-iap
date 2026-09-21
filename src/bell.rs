//! The terminal bell, rung when a request stops on a human.
//!
//! An `ask` rule parks a request and denies it if nobody answers in time. That
//! is the right way for it to fail, but it makes the console's usefulness
//! depend on somebody happening to be looking at it: a request that arrives
//! while the operator is in another window times out, and the agent is told no
//! for a reason nobody ever saw. A terminal in the background cannot be seen.
//! It can be heard.
//!
//! `BEL` — one byte, `0x07` — is how a terminal has been asked to get
//! attention since teletypes, and what it does with it is the operator's
//! setting, not this program's: a sound, a flashing window, a dock badge, a
//! tmux window flagged with `#{?window_bell_flag}`, a desktop notification
//! from a terminal wired up that way. All of those are the right answer for
//! somebody, and none of them is something this process has to implement, ship
//! a dependency for, or get permission from an operating system to do.
//!
//! Two things keep it from becoming noise:
//!
//! - **It is rate-limited.** An agent that trips an `ask` rule in a loop
//!   parks a dozen requests in a second, and a dozen beeps is a sound an
//!   operator turns off — after which the feature is worse than not having it,
//!   because the queue is now silent *and* nobody is watching it.
//! - **It is refusable**, per run with `--no-bell`, for good with
//!   `IAP_NO_BELL`, and in the policy file with `approval_bell = false`.
//!
//! It is also never rung at a terminal nobody is watching: a proxy running
//! under a unit file has no business beeping at whoever owns the console it
//! was started from.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// `BEL`. One byte, and the oldest interface in this program.
pub const BEL: &str = "\x07";

/// The shortest gap between two rings.
///
/// An agent retrying a denied call parks requests far faster than a human
/// reads them, and the point of the bell is to be noticed once — the console
/// is what says how many are waiting. Long enough that a burst is one sound,
/// short enough that a second request a few seconds later still gets its own.
pub const QUIET: Duration = Duration::from_secs(3);

/// Has the operator turned this off for good?
///
/// Any value but the explicitly falsey ones counts, matching
/// `IAP_NO_CLIPBOARD`: somebody exporting `IAP_NO_BELL=1` and somebody
/// exporting `IAP_NO_BELL=yes` mean the same thing, and a variable set to
/// nothing at all is the shell's usual way of having unset it.
pub fn disabled_by_environment() -> bool {
    match std::env::var("IAP_NO_BELL") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}

/// Why a ring did not make a sound — or that it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// The byte reached the terminal. Whether the terminal did anything with
    /// it is the operator's setting, and not knowable from here.
    Sent,
    /// Turned off: `approval_bell = false`, `--no-bell`, or `IAP_NO_BELL`.
    Declined,
    /// Another request rang within `QUIET`, and one sound is the point.
    TooSoon,
    /// Nobody is watching this process: output is a pipe, a file, a journal.
    NoTerminal,
    /// A terminal was there and the write to it failed.
    Failed,
}

impl Rung {
    pub fn sounded(self) -> bool {
        matches!(self, Rung::Sent)
    }
}

/// The bell, and the last time it rang.
///
/// Shared by everything that can park a request, so the rate limit is one
/// budget rather than one per caller — two surfaces each ringing "only once"
/// is two beeps.
pub struct Bell {
    /// Editable while running: `approval_bell` is a line in the policy file,
    /// and the file is re-read under a running proxy.
    enabled: AtomicBool,
    last: Mutex<Option<Instant>>,
}

impl Bell {
    /// `enabled` is the policy file's say plus the command line's. The
    /// environment is checked at every ring instead, so that a call site
    /// cannot forget to honour it.
    pub fn new(enabled: bool) -> Self {
        Bell {
            enabled: AtomicBool::new(enabled),
            last: Mutex::new(None),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) && !disabled_by_environment()
    }

    /// Ring, unless something says not to.
    ///
    /// Best-effort by construction: nothing upstream of this waits on the
    /// result, and a request must never be held up — let alone refused —
    /// because a terminal would not take a byte.
    pub fn ring(&self) -> Rung {
        if !self.enabled() {
            return Rung::Declined;
        }
        if !crate::term::attached() {
            return Rung::NoTerminal;
        }
        if !self.claim() {
            return Rung::TooSoon;
        }
        match crate::term::write(BEL) {
            true => Rung::Sent,
            false => Rung::Failed,
        }
    }

    /// Take this ring's turn, if the quiet period has passed.
    ///
    /// Tested and claimed under one guard: two requests parking at the same
    /// moment must produce one sound, not two that both read a stale `last`
    /// and both decide they are the first.
    fn claim(&self) -> bool {
        let mut last = self.last.lock();
        if last.is_some_and(|at| at.elapsed() < QUIET) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bell_is_one_byte() {
        // Not an escape sequence: a terminal that understands nothing else
        // understands this, which is the whole reason it is what is used.
        assert_eq!(BEL.as_bytes(), &[0x07]);
    }

    #[test]
    fn turned_off_means_nothing_is_written() {
        // No terminal is opened and no clock is read: a policy that says no
        // has already answered the question.
        let bell = Bell::new(false);
        assert!(!bell.enabled());
        assert_eq!(bell.ring(), Rung::Declined);
    }

    #[test]
    fn it_can_be_turned_back_on_under_a_running_proxy() {
        let bell = Bell::new(false);
        bell.set_enabled(true);
        // Not `Sent`: the test runner has no terminal, which is exactly the
        // refusal a unit file gets. What matters is that it got that far.
        assert_ne!(bell.ring(), Rung::Declined);
    }

    /// The rate limit on its own, rather than through `ring` — which refuses
    /// first for having no terminal, this being a test runner.
    #[test]
    fn a_burst_of_requests_is_one_sound() {
        let bell = Bell::new(true);
        assert!(bell.claim(), "the first one rings");
        assert!(!bell.claim(), "and the one a moment later does not");
    }

    #[test]
    fn a_ring_after_the_quiet_period_sounds_again() {
        let bell = Bell::new(true);
        assert!(bell.claim());
        // Far enough back that the quiet period is over. Rewound rather than
        // slept through: three seconds is a long test for a constant.
        *bell.last.lock() = Instant::now().checked_sub(QUIET * 2);
        assert!(bell.claim());
    }

    #[test]
    fn a_proxy_nobody_is_watching_does_not_beep_at_whoever_started_it() {
        // A unit file has no terminal, and the refusal has to come before the
        // rate limit claims a turn — otherwise a run with no terminal at all
        // would silence the first real ring after one is attached.
        let bell = Bell::new(true);
        if !crate::term::attached() {
            assert_eq!(bell.ring(), Rung::NoTerminal);
            assert!(bell.claim(), "and nothing took this ring's turn");
        }
    }
}
