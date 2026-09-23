//! What this binary was built from, recorded at build time.
//!
//! `--version` printed `2026.9.0` and nothing else, which is the same string
//! for every build of every commit between two releases. An operator running a
//! binary they built themselves — which is how this is installed, there being
//! no tagged release yet — therefore had no way at all to answer "does the
//! thing I am running contain the fix?". Three rounds of a bug report were
//! spent on that question without either side being able to settle it
//! (SIRI-205).
//!
//! So the commit and the build date go in. Both are optional: a build from a
//! source tarball has no git, and a reproducible build wants the date pinned
//! rather than taken from the clock. Neither absence is an error — `version`
//! falls back to the bare package version, which is what it printed before.

use std::process::Command;

fn main() {
    // Only re-run when the commit could have changed. Without this the build
    // script runs on every `cargo build`, which costs two `git` processes for
    // a string that is usually the same one.
    for path in [".git/HEAD", ".git/refs/heads"] {
        if std::path::Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    println!("cargo:rerun-if-env-changed=AGENT_IAP_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    if let Some(commit) = commit() {
        println!("cargo:rustc-env=AGENT_IAP_COMMIT={commit}");
    }
    if let Some(date) = build_date() {
        println!("cargo:rustc-env=AGENT_IAP_BUILD_DATE={date}");
    }
}

/// The commit, with a mark when the tree had uncommitted changes in it —
/// "the fix is in that commit" is not an answer about a tree that has been
/// edited since.
fn commit() -> Option<String> {
    // A packager who has no `.git` can say what it was built from instead.
    if let Ok(given) = std::env::var("AGENT_IAP_BUILD_COMMIT") {
        if !given.trim().is_empty() {
            return Some(given.trim().to_string());
        }
    }
    let short = run(&["rev-parse", "--short=12", "HEAD"])?;
    let dirty = run(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|changes| !changes.is_empty());
    Some(match dirty {
        true => format!("{short}-modified"),
        false => short,
    })
}

/// The day it was built, or the day the source was stamped for a build meant
/// to be reproducible.
fn build_date() -> Option<String> {
    let seconds: i64 = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(stamped) => stamped.trim().parse().ok()?,
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64,
    };
    // Days since the epoch to a calendar date, without a dependency: this is
    // the whole of what a build script needs a date library for.
    let days = seconds.div_euclid(86_400);
    Some(civil_date(days))
}

/// `1970-01-01 + days`, as `YYYY-MM-DD`.
fn civil_date(days: i64) -> String {
    // Howard Hinnant's civil-from-days, shifted to an era beginning in March so
    // the leap day lands at the end of a year and the month lengths repeat.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

fn run(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
