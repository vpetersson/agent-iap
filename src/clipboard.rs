//! Putting a minted token on the operator's clipboard, through the terminal.
//!
//! A token is printed exactly once and then has to get somewhere else — an
//! agent's environment, a password manager, another host's shell. The step in
//! between is a human selecting forty-eight hex characters with a mouse, which
//! is the one part of enrolling an agent that can silently go wrong: a dropped
//! leading character produces a token that authenticates nothing, and the
//! plaintext it came from is gone.
//!
//! OSC 52 is the terminal's own answer. The program writes
//! `ESC ] 52 ; c ; <base64> BEL` to the terminal and the *terminal* — not this
//! process, and not the kernel it happens to be running on — puts the payload
//! on the clipboard of whoever is looking at it. That is the property worth
//! having: it works identically over SSH, inside a container, and from a tmux
//! pane on a jump host, none of which have a clipboard of their own for a
//! `pbcopy` to reach. xterm, kitty, foot, Alacritty, WezTerm, iTerm2, Ghostty,
//! Windows Terminal and VS Code's terminal all implement it; tmux and screen
//! forward it when asked in the dialect each one wants, which is what `Relay`
//! is for — and for tmux that means asking both ways, because which one a pane
//! answers to is a line in somebody else's `tmux.conf`.
//!
//! Two things it is not:
//!
//! - **Confirmable.** The sequence is one-way. A terminal that does not
//!   implement it drops the bytes and says nothing, so the most this module
//!   can honestly report is that the write succeeded — never that the clipboard
//!   changed. Every message built on top of it says so.
//! - **Free of consequence.** The token lands in a desktop clipboard, which is
//!   readable by anything else on that desktop and is often kept in a history
//!   by a clipboard manager. That is a fair trade for a token that authorises
//!   nothing off this proxy and can be rotated with one command — but it is the
//!   operator's trade to refuse, so `IAP_NO_CLIPBOARD` and `--no-clipboard`
//!   turn it off, and nothing is ever copied without a line saying it was.

/// The escape sequence's ceiling, in bytes of base64.
///
/// xterm's is the smallest in common use and everything else is more generous.
/// An agent token is under a hundred bytes, so this can only ever be hit by a
/// caller that is copying something it should not be; refusing beats writing a
/// truncated secret into a clipboard and reporting success.
const MAX_ENCODED: usize = 74_994;

/// Which dialect the terminal on the other end speaks.
///
/// A multiplexer sits between this process and the terminal that owns the
/// clipboard, and will not forward an escape sequence it does not recognise as
/// something to forward. Each one has its own way of being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relay {
    /// Straight to the terminal.
    None,
    /// tmux, which has two ways of being asked and enables one of them by
    /// default — see `sequence`, which asks both ways.
    Tmux,
    /// GNU screen, whose DCS passthrough has a length limit, so a long payload
    /// arrives as several of them in a row.
    Screen,
}

/// What happened, in enough detail for the caller to say something true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Copied {
    /// The sequence reached the terminal. Whether the terminal did anything
    /// with it is not knowable from here.
    Sent,
    /// Turned off by `IAP_NO_CLIPBOARD`, or by the caller's own flag.
    Declined,
    /// Nobody is watching: output is a pipe, a file, a unit's journal.
    NoTerminal,
    /// Too long to be a token. Nothing was written.
    TooLarge,
    /// A terminal was there and the write to it failed.
    Failed,
}

impl Copied {
    pub fn sent(self) -> bool {
        matches!(self, Copied::Sent)
    }

    /// The line to print under a token, or `None` when the right thing to say
    /// is nothing.
    ///
    /// Silence is deliberate for the ordinary refusals: an operator who set
    /// `IAP_NO_CLIPBOARD` does not need telling on every mint, and a run with
    /// its output redirected is usually a script, where a note about a
    /// clipboard is noise in a file someone will read later.
    pub fn note(self) -> Option<&'static str> {
        match self {
            Copied::Sent => Some(
                "Copied to your clipboard. OSC 52 is one-way, so paste it somewhere to be sure \
                 it arrived.",
            ),
            Copied::Failed => Some("Could not write to the terminal, so nothing was copied."),
            Copied::TooLarge => Some("Too long to copy over OSC 52, so nothing was copied."),
            Copied::Declined | Copied::NoTerminal => None,
        }
    }
}

/// Has the operator turned this off?
///
/// Any value but the explicitly falsey ones counts: somebody exporting
/// `IAP_NO_CLIPBOARD=1` and somebody exporting `IAP_NO_CLIPBOARD=yes` mean the
/// same thing, and a variable set to nothing at all is the shell's usual way of
/// having unset it.
pub fn disabled_by_environment() -> bool {
    match std::env::var("IAP_NO_CLIPBOARD") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}

/// Copy, unless the operator asked not to.
///
/// `allowed` is the caller's own say — a `--no-clipboard` flag, or a mode in
/// which copying makes no sense. The environment is checked here so that every
/// call site honours it without having to remember to.
pub fn copy(text: &str, allowed: bool) -> Copied {
    if !allowed || disabled_by_environment() {
        return Copied::Declined;
    }
    // Nobody looking at this process means the output is going somewhere
    // nobody is watching right now — a file, a pipe, a CI log. `/dev/tty`
    // might still open in that case, but writing to it would put a secret on
    // the clipboard of whoever happens to own the session, for a command they
    // are not watching.
    if !crate::term::attached() {
        return Copied::NoTerminal;
    }
    let Some(sequence) = sequence(text, relay()) else {
        return Copied::TooLarge;
    };
    match crate::term::write(&sequence) {
        true => Copied::Sent,
        false => Copied::Failed,
    }
}

fn term() -> String {
    std::env::var("TERM").unwrap_or_default()
}

/// What is between this process and the clipboard, right now.
///
/// Public because the copy itself is unconfirmable: when an operator says
/// nothing arrived, the only useful thing left to tell them is which
/// multiplexer to go and configure, and that is this answer.
pub fn relay() -> Relay {
    relay_from(std::env::var_os("TMUX").is_some(), &term())
}

/// Which multiplexer, if any, is in the way.
///
/// `TMUX` is set inside a tmux pane and nowhere else, so it is the reliable
/// signal; screen only leaves `TERM`, which tmux also sets to `screen…` under
/// its default terminal setting — hence the order.
pub fn relay_from(tmux_env: bool, term: &str) -> Relay {
    if tmux_env {
        Relay::Tmux
    } else if term.starts_with("screen") {
        Relay::Screen
    } else {
        Relay::None
    }
}

/// The bytes to write, or `None` if the payload is too long to be worth
/// writing.
///
/// `c` is the selection: the clipboard proper, rather than the X primary
/// selection a bare `ESC ] 52 ; ; …` would target on some terminals.
pub fn sequence(text: &str, relay: Relay) -> Option<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let encoded = STANDARD.encode(text.as_bytes());
    if encoded.len() > MAX_ENCODED {
        return None;
    }
    // BEL rather than ST terminates it: both are legal, and BEL is what the
    // terminals that only implement one of the two implement.
    let osc = format!("\x1b]52;c;{encoded}\x07");

    Some(match relay {
        Relay::None => osc,
        // Both ways of asking tmux, because which one works is a setting in
        // somebody else's config file and neither is safe to assume:
        //
        // - The bare sequence, which tmux forwards itself when `set-clipboard`
        //   is `on` or `external`. `external` is the default, so this is the
        //   one that usually works.
        // - Its DCS passthrough, which replays the contents outward verbatim —
        //   hence the doubled `ESC`s, so the inner ones survive being parsed
        //   once on the way through. `allow-passthrough` has defaulted to *off*
        //   since tmux 3.3, so sending only this is how a copy inside tmux
        //   silently does nothing, which is what it did.
        //
        // A pane with both enabled sends the terminal the same payload twice
        // and the second write lands on the same clipboard as the first. That
        // is the cost, and it is the right way round: a duplicate write is
        // invisible, and a token that did not copy is a token that is gone.
        Relay::Tmux => format!("{osc}\x1bPtmux;{}\x1b\\", osc.replace('\x1b', "\x1b\x1b")),
        // screen's passthrough takes the sequence verbatim, but caps how much
        // of it fits in one DCS. Ending and reopening mid-sequence is how the
        // rest gets across.
        Relay::Screen => {
            let mut wrapped = String::from("\x1bP");
            for (index, chunk) in chunks(&osc, SCREEN_CHUNK).enumerate() {
                if index > 0 {
                    wrapped.push_str("\x1b\\\x1bP");
                }
                wrapped.push_str(chunk);
            }
            wrapped.push_str("\x1b\\");
            wrapped
        }
    })
}

/// How much of a sequence fits in one of screen's DCS strings. Its buffer is
/// 768 bytes; this leaves room for the wrapper around each chunk.
const SCREEN_CHUNK: usize = 496;

/// Split on byte boundaries. Sound because everything passed here is base64
/// and ASCII punctuation, and cheap enough not to need to be clever about it.
fn chunks(text: &str, size: usize) -> impl Iterator<Item = &str> {
    text.as_bytes()
        .chunks(size)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "iap_0123456789abcdef";
    /// base64("iap_0123456789abcdef")
    const ENCODED: &str = "aWFwXzAxMjM0NTY3ODlhYmNkZWY=";

    #[test]
    fn a_bare_terminal_gets_the_sequence_itself() {
        let sequence = sequence(TOKEN, Relay::None).expect("a token is not too long");
        assert_eq!(sequence, format!("\x1b]52;c;{ENCODED}\x07"));
    }

    #[test]
    fn the_clipboard_is_asked_for_by_name() {
        // `c`, not the empty selection: the empty one means "whatever the
        // terminal defaults to", which on some is the primary selection.
        let sequence = sequence(TOKEN, Relay::None).unwrap();
        assert!(sequence.starts_with("\x1b]52;c;"), "{sequence:?}");
    }

    #[test]
    fn tmux_gets_a_passthrough_with_its_escapes_doubled() {
        let sequence = sequence(TOKEN, Relay::Tmux).unwrap();
        assert!(
            sequence.contains(&format!("\x1bPtmux;\x1b\x1b]52;c;{ENCODED}\x07\x1b\\")),
            "{sequence:?}"
        );
    }

    /// The regression: a pane with tmux's defaults only ever sees the bare
    /// sequence, because `allow-passthrough` is off and `set-clipboard` is not.
    /// Sending the passthrough alone is a copy that silently does nothing.
    #[test]
    fn tmux_also_gets_the_bare_sequence_it_forwards_by_default() {
        let sequence = sequence(TOKEN, Relay::Tmux).unwrap();
        let bare = format!("\x1b]52;c;{ENCODED}\x07");
        assert!(sequence.starts_with(&bare), "{sequence:?}");
        // And the two are separable: the bare one first, then the wrapper, so
        // a tmux that acts on neither is the only one that copies nothing.
        assert_eq!(
            &sequence[bare.len()..],
            format!("\x1bPtmux;\x1b\x1b]52;c;{ENCODED}\x07\x1b\\")
        );
    }

    #[test]
    fn screen_gets_one_dcs_when_the_payload_is_short() {
        let sequence = sequence(TOKEN, Relay::Screen).unwrap();
        assert_eq!(sequence, format!("\x1bP\x1b]52;c;{ENCODED}\x07\x1b\\"));
    }

    #[test]
    fn screen_gets_several_when_it_is_long() {
        let long = "a".repeat(4_000);
        let wrapped = sequence(&long, Relay::Screen).unwrap();
        // Opened once per chunk, closed once per chunk, and the payload is
        // still all there once the wrappers are taken back off.
        let opens = wrapped.matches("\x1bP").count();
        assert!(opens > 1, "expected several chunks, got {opens}");
        assert_eq!(wrapped.matches("\x1b\\").count(), opens);
        let rejoined = wrapped
            .trim_start_matches("\x1bP")
            .trim_end_matches("\x1b\\")
            .replace("\x1b\\\x1bP", "");
        assert_eq!(rejoined, sequence(&long, Relay::None).unwrap());
    }

    #[test]
    fn nothing_absurdly_long_is_written_at_all() {
        // Well past any terminal's buffer: a truncated secret on the clipboard
        // would be reported as a success, which is worse than refusing.
        assert!(sequence(&"a".repeat(MAX_ENCODED), Relay::None).is_none());
    }

    #[test]
    fn tmux_wins_over_the_term_it_sets() {
        // tmux's own default `TERM` is `screen-256color`, so a pane would be
        // taken for screen if `TMUX` were not checked first.
        assert_eq!(relay_from(true, "screen-256color"), Relay::Tmux);
        assert_eq!(relay_from(false, "screen.xterm-256color"), Relay::Screen);
        assert_eq!(relay_from(false, "xterm-256color"), Relay::None);
        assert_eq!(relay_from(false, ""), Relay::None);
    }

    #[test]
    fn the_callers_own_no_is_enough() {
        // No terminal is opened and no environment is read: a caller that says
        // no has already answered the question.
        assert_eq!(copy(TOKEN, false), Copied::Declined);
    }

    #[test]
    fn only_the_outcomes_worth_a_line_get_one() {
        assert!(Copied::Sent.note().is_some());
        assert!(Copied::Failed.note().is_some());
        assert!(Copied::TooLarge.note().is_some());
        assert!(Copied::Declined.note().is_none());
        assert!(Copied::NoTerminal.note().is_none());
    }
}
