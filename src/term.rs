//! Writing to the terminal a human is looking at, rather than to this
//! process's output.
//!
//! Two things here want the same handle for two different reasons, and both of
//! them would be wrong to write on stdout: `clipboard` puts a token on the
//! operator's clipboard with OSC 52, and `bell` rings when a request stops on
//! a human. Neither is program output — an operator is entitled to redirect
//! stdout into a file without finding an escape sequence in the middle of the
//! token they saved — and under the console ratatui owns stdout anyway.
//!
//! `/dev/tty` is the answer to both: it is the session's terminal whatever the
//! standard streams were pointed at.

use std::io::{IsTerminal, Write};

/// Is anybody looking at this process right now?
///
/// Neither standard stream being a terminal means the output is going
/// somewhere nobody is watching — a file, a pipe, a unit's journal. `/dev/tty`
/// might still open in that case, and writing to it would put an escape
/// sequence, or a beep, on the session of whoever happens to own the terminal
/// for a command they are not watching.
pub fn attached() -> bool {
    std::io::stdout().is_terminal() || std::io::stderr().is_terminal()
}

/// Write straight to the terminal, reporting whether the bytes got there.
///
/// Never that they had any effect: both callers send escape sequences a
/// terminal is free to ignore silently, so "written" is the most that can
/// honestly be claimed from in here.
pub fn write(sequence: &str) -> bool {
    #[cfg(unix)]
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        return tty
            .write_all(sequence.as_bytes())
            .and_then(|()| tty.flush())
            .is_ok();
    }
    // No controlling terminal to open, or not a platform that has one. Stderr
    // is the fallback because it is the stream that is still a terminal when
    // stdout has been redirected, and because it is not anybody's output.
    let mut stderr = std::io::stderr();
    if !stderr.is_terminal() {
        return false;
    }
    stderr
        .write_all(sequence.as_bytes())
        .and_then(|()| stderr.flush())
        .is_ok()
}
