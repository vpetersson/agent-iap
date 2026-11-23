//! When a rule applies: days of the week, hours of the day, in a named zone.
//!
//! `expires` ends a grant once. A schedule opens and closes one on the clock,
//! every week: a backup agent that may write to the bucket between 03:00 and
//! 05:00, a reporting agent that may read the warehouse on weekdays. Outside
//! its window a scheduled rule matches nothing, exactly like an expired one, so
//! the request falls through to whatever is behind it — the `ask` or `deny`
//! that a rule in front of it was written to relax.
//!
//! The window is wall-clock time somewhere, so the zone is part of it and is
//! never assumed. "03:00" on a laptop in Stockholm and "03:00" in a container
//! whose clock is UTC are two different hours, and a rule that silently meant
//! the second when it was written about the first opens an hour or two early —
//! the direction that widens.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Timelike, Utc};
use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};

const MINUTES_PER_DAY: u16 = 24 * 60;

/// A rule's `schedule`, parsed and checked.
///
/// Parsing happens when the policy file loads, so a `25:00` or a misspelt zone
/// stops the file there — with the line it is on — rather than producing a rule
/// that never opens and a denial on the first call that names nothing.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "RawSchedule", into = "RawSchedule")]
pub struct Schedule {
    /// Bit `n` is `Weekday::num_days_from_monday() == n`. All seven when the
    /// file named no days.
    days: u8,
    /// Empty means the whole of each day `days` allows.
    hours: Vec<Window>,
    zone: Zone,
    /// What the file said, so writing the rule back out says the same thing.
    raw: RawSchedule,
}

/// The TOML spelling: `schedule = { days = ["mon-fri"], hours = ["03:00-05:00"], tz = "Europe/London" }`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSchedule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tz: Option<String>,
}

/// `[start, end)` in minutes past local midnight. `end <= start` crosses
/// midnight, and belongs to the day it *started* on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    start: u16,
    end: u16,
}

#[derive(Debug, Clone)]
enum Zone {
    /// This machine's clock, asked for by name rather than fallen back to.
    Local,
    /// The canonical IANA name, and the zone it resolved to in the bundled
    /// database.
    Named(String, TimeZone),
}

impl PartialEq for Zone {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Zone::Local, Zone::Local) => true,
            (Zone::Named(a, _), Zone::Named(b, _)) => a == b,
            _ => false,
        }
    }
}

impl TryFrom<RawSchedule> for Schedule {
    type Error = anyhow::Error;

    fn try_from(raw: RawSchedule) -> Result<Self> {
        let tz = raw.tz.as_deref().map(str::trim).filter(|tz| !tz.is_empty());
        let Some(tz) = tz else {
            bail!(
                "a schedule needs `tz` — an IANA zone such as \"Europe/London\", \"UTC\", or \
                 \"local\" for this machine's clock. The hours mean nothing until it says whose"
            );
        };
        let zone = parse_zone(tz)?;

        if raw.days.is_none() && raw.hours.is_none() {
            bail!(
                "a schedule with neither `days` nor `hours` is always open — leave `schedule` \
                 out, or say when the rule applies"
            );
        }

        let days = match &raw.days {
            None => 0b111_1111,
            Some(list) => {
                if list.is_empty() {
                    bail!("`days = []` is a rule that never applies — name at least one day");
                }
                let mut bits = 0u8;
                for item in list {
                    bits |= parse_days(item)?;
                }
                bits
            }
        };

        let hours = match &raw.hours {
            None => Vec::new(),
            Some(list) => {
                if list.is_empty() {
                    bail!(
                        "`hours = []` is a rule that never applies — name a window such as \
                         \"03:00-05:00\", or leave `hours` out for the whole day"
                    );
                }
                list.iter()
                    .map(|item| parse_window(item))
                    .collect::<Result<_>>()?
            }
        };

        Ok(Schedule {
            days,
            hours,
            zone,
            raw,
        })
    }
}

impl From<Schedule> for RawSchedule {
    fn from(schedule: Schedule) -> Self {
        schedule.raw
    }
}

impl Schedule {
    /// Build one from what an operator typed: `acl add --days … --hours … --tz …`,
    /// or the console's form. `None` when none of the three was given.
    pub fn from_parts(days: &[String], hours: &[String], tz: Option<&str>) -> Result<Option<Self>> {
        let tz = tz.map(str::trim).filter(|tz| !tz.is_empty());
        if days.is_empty() && hours.is_empty() && tz.is_none() {
            return Ok(None);
        }
        let list = |items: &[String]| -> Option<Vec<String>> {
            let items: Vec<String> = items
                .iter()
                .flat_map(|item| item.split(','))
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect();
            (!items.is_empty()).then_some(items)
        };
        Schedule::try_from(RawSchedule {
            days: list(days),
            hours: list(hours),
            tz: tz.map(str::to_string),
        })
        .map(Some)
    }

    pub fn raw(&self) -> &RawSchedule {
        &self.raw
    }

    /// Is the window open at this instant?
    pub fn contains(&self, now: DateTime<Utc>) -> bool {
        let (day, minute) = self.local(now);
        let today = self.allows(day);
        if self.hours.is_empty() {
            return today;
        }
        let yesterday = self.allows((day + 6) % 7);
        self.hours.iter().any(|window| {
            if window.start < window.end {
                today && (window.start..window.end).contains(&minute)
            } else {
                (today && minute >= window.start) || (yesterday && minute < window.end)
            }
        })
    }

    /// The next instant the window opens or closes, within a week and a day.
    /// For display only — `contains` is what decides.
    ///
    /// Walked a minute at a time: every boundary a schedule can name falls on
    /// a minute, and the zone's own transitions (a daylight-saving jump) are
    /// whatever `contains` says they are, without this having to model them.
    pub fn next_change(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let open = self.contains(now);
        let start = now.with_second(0)?.with_nanosecond(0)?;
        (1..=(8 * MINUTES_PER_DAY as i64))
            .map(|minutes| start + chrono::TimeDelta::minutes(minutes))
            .find(|at| self.contains(*at) != open)
    }

    /// `open, closes in 1h12m` / `closed, opens in 3h` — what a reader deciding
    /// about this rule right now wants, without converting a zone in their head.
    pub fn status(&self, now: DateTime<Utc>) -> String {
        let open = self.contains(now);
        let word = if open { "open" } else { "closed" };
        match self.next_change(now) {
            Some(at) => format!(
                "{word}, {} in {}",
                if open { "closes" } else { "opens" },
                crate::enroll::remaining(at, now)
            ),
            None => word.to_string(),
        }
    }

    /// `day` counts from Monday = 0.
    fn allows(&self, day: u8) -> bool {
        self.days & (1 << day) != 0
    }

    /// The day (Monday = 0) and minute past midnight it is in this zone.
    fn local(&self, now: DateTime<Utc>) -> (u8, u16) {
        let tz = match &self.zone {
            Zone::Local => TimeZone::system(),
            Zone::Named(_, tz) => tz.clone(),
        };
        // Whole seconds are all a schedule can name, and every instant a
        // `DateTime<Utc>` holds is one jiff can, so this cannot fail; a clock
        // so far out of range that it did would leave the window shut.
        let Ok(at) = jiff::Timestamp::from_second(now.timestamp()) else {
            return (0, u16::MAX);
        };
        let at = tz.to_datetime(at);
        (
            at.weekday().to_monday_zero_offset() as u8,
            at.hour() as u16 * 60 + at.minute() as u16,
        )
    }
}

/// `mon-fri 03:00-05:00 Europe/London` — the same words on every surface: the
/// rule list, `check`, and the sentence a refusal ends with.
impl std::fmt::Display for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.days != 0b111_1111 {
            parts.push(describe_days(self.days));
        }
        if !self.hours.is_empty() {
            parts.push(
                self.hours
                    .iter()
                    .map(|w| format!("{}-{}", clock(w.start), clock(w.end)))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        parts.push(match &self.zone {
            Zone::Local => "local time".to_string(),
            Zone::Named(name, _) => name.clone(),
        });
        f.write_str(&parts.join(" "))
    }
}

fn parse_zone(text: &str) -> Result<Zone> {
    if text.eq_ignore_ascii_case("local") {
        return Ok(Zone::Local);
    }
    if text.eq_ignore_ascii_case("utc") || text == "Z" {
        return Ok(Zone::Named("UTC".into(), TimeZone::UTC));
    }
    let tz = TimeZone::get(text).map_err(|_| {
        anyhow::anyhow!(
            "`{text}` is not a time zone this build knows — use an IANA name such as \
             \"Europe/London\" or \"America/New_York\", \"UTC\", or \"local\""
        )
    })?;
    // The database's spelling, so `europe/london` in the file still reads
    // back as the zone a reader would search for.
    let name = tz.iana_name().unwrap_or(text).to_string();
    Ok(Zone::Named(name, tz))
}

const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn parse_day(text: &str) -> Result<u8> {
    let lower = text.trim().to_ascii_lowercase();
    let full = [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];
    DAY_NAMES
        .iter()
        .zip(full)
        .position(|(short, long)| lower == *short || lower == long)
        .map(|n| n as u8)
        .with_context(|| {
            format!(
                "`{}` is not a day — use mon, tue, wed, thu, fri, sat or sun",
                text.trim()
            )
        })
}

/// `wed`, or a range `mon-fri`. A range may wrap: `fri-mon` is four days.
fn parse_days(text: &str) -> Result<u8> {
    let text = text.trim();
    let Some((from, to)) = text.split_once('-') else {
        return Ok(1 << parse_day(text)?);
    };
    let (from, to) = (parse_day(from)?, parse_day(to)?);
    let mut bits = 0u8;
    let mut day = from;
    loop {
        bits |= 1 << day;
        if day == to {
            break;
        }
        day = (day + 1) % 7;
    }
    Ok(bits)
}

fn parse_time(text: &str, end: bool) -> Result<u16> {
    let text = text.trim();
    let (h, m) = text
        .split_once(':')
        .with_context(|| format!("`{text}` is not a time — write it as HH:MM, e.g. 03:00"))?;
    let h: u16 = h
        .parse()
        .with_context(|| format!("`{text}` is not a time — write it as HH:MM, e.g. 03:00"))?;
    let m: u16 = m
        .parse()
        .with_context(|| format!("`{text}` is not a time — write it as HH:MM, e.g. 03:00"))?;
    // `24:00` closes a window at midnight; it opens none.
    if end && h == 24 && m == 0 {
        return Ok(MINUTES_PER_DAY);
    }
    if h > 23 || m > 59 || text.split_once(':').is_some_and(|(_, m)| m.len() != 2) {
        bail!("`{text}` is not a time of day — hours run 00-23 and minutes 00-59");
    }
    Ok(h * 60 + m)
}

/// `03:00-05:00`, or one that crosses midnight: `22:00-02:00`.
fn parse_window(text: &str) -> Result<Window> {
    let text = text.trim();
    let (start, end) = text.split_once('-').with_context(|| {
        format!("`{text}` is not a window — write it as HH:MM-HH:MM, e.g. 03:00-05:00")
    })?;
    let start = parse_time(start, false)?;
    let end = parse_time(end, true)?;
    if start == end {
        bail!(
            "`{text}` starts and ends at the same minute, which could mean no time or all day — \
             leave `hours` out for the whole day"
        );
    }
    Ok(Window { start, end })
}

fn clock(minutes: u16) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

/// `mon-fri`, `sat,sun`, `mon,wed-fri` — runs of three or more as a range.
fn describe_days(bits: u8) -> String {
    let mut out = Vec::new();
    let mut day = 0;
    while day < 7 {
        if bits & (1 << day) == 0 {
            day += 1;
            continue;
        }
        let start = day;
        while day + 1 < 7 && bits & (1 << (day + 1)) != 0 {
            day += 1;
        }
        match day - start {
            0 => out.push(DAY_NAMES[start].to_string()),
            1 => {
                out.push(DAY_NAMES[start].to_string());
                out.push(DAY_NAMES[day].to_string());
            }
            _ => out.push(format!("{}-{}", DAY_NAMES[start], DAY_NAMES[day])),
        }
        day += 1;
    }
    out.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(days: &[&str], hours: &[&str], tz: &str) -> Schedule {
        let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Schedule::from_parts(&strings(days), &strings(hours), Some(tz))
            .unwrap()
            .unwrap()
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    #[test]
    fn a_window_is_open_from_its_start_up_to_but_not_including_its_end() {
        let nightly = schedule(&[], &["03:00-05:00"], "UTC");
        assert!(!nightly.contains(at("2026-11-23T02:59:59Z")));
        assert!(nightly.contains(at("2026-11-23T03:00:00Z")));
        assert!(nightly.contains(at("2026-11-23T04:59:59Z")));
        assert!(!nightly.contains(at("2026-11-23T05:00:00Z")));
    }

    #[test]
    fn the_hours_are_the_named_zones_wall_clock_including_across_daylight_saving() {
        let nightly = schedule(&[], &["03:00-05:00"], "Europe/Stockholm");
        // Winter: CET, UTC+1.
        assert!(nightly.contains(at("2026-11-23T02:30:00Z")));
        assert!(!nightly.contains(at("2026-11-23T04:30:00Z")));
        // Summer: CEST, UTC+2. Same wall clock, a different UTC hour.
        assert!(nightly.contains(at("2026-07-01T01:30:00Z")));
        assert!(!nightly.contains(at("2026-07-01T03:30:00Z")));
    }

    #[test]
    fn days_are_the_zones_days_not_utcs() {
        // 23:30 UTC on Friday is already Saturday in Tokyo.
        let weekend = schedule(&["sat", "sun"], &[], "Asia/Tokyo");
        assert!(weekend.contains(at("2026-11-27T23:30:00Z")));
        let weekend_utc = schedule(&["sat", "sun"], &[], "UTC");
        assert!(!weekend_utc.contains(at("2026-11-27T23:30:00Z")));
    }

    #[test]
    fn a_window_across_midnight_belongs_to_the_day_it_opened_on() {
        // Friday night into Saturday morning, and no other night.
        let friday_night = schedule(&["fri"], &["22:00-02:00"], "UTC");
        assert!(friday_night.contains(at("2026-11-27T23:00:00Z"))); // Fri 23:00
        assert!(friday_night.contains(at("2026-11-28T01:59:00Z"))); // Sat 01:59
        assert!(!friday_night.contains(at("2026-11-28T02:00:00Z")));
        assert!(!friday_night.contains(at("2026-11-28T23:00:00Z"))); // Sat 23:00
        assert!(!friday_night.contains(at("2026-11-27T01:00:00Z"))); // Fri 01:00 is Thursday's night
    }

    #[test]
    fn day_ranges_include_both_ends_and_may_wrap_the_week() {
        assert_eq!(parse_days("mon-fri").unwrap(), 0b001_1111);
        assert_eq!(parse_days("fri-mon").unwrap(), 0b111_0001);
        assert_eq!(parse_days("Wednesday").unwrap(), 0b000_0100);
        assert_eq!(describe_days(0b001_1111), "mon-fri");
        assert_eq!(describe_days(0b110_0000), "sat,sun");
        assert_eq!(describe_days(0b001_1101), "mon,wed-fri");
    }

    #[test]
    fn it_reads_back_in_one_line() {
        let s = schedule(
            &["mon-fri"],
            &["03:00-05:00", "22:00-24:00"],
            "Europe/London",
        );
        assert_eq!(
            s.to_string(),
            "mon-fri 03:00-05:00,22:00-24:00 Europe/London"
        );
        assert_eq!(
            schedule(&["sat,sun"], &[], "local").to_string(),
            "sat,sun local time"
        );
    }

    #[test]
    fn the_status_says_when_it_next_changes() {
        let nightly = schedule(&[], &["03:00-05:00"], "UTC");
        assert_eq!(
            nightly.status(at("2026-11-23T00:00:00Z")),
            "closed, opens in 3h0m"
        );
        assert_eq!(
            nightly.status(at("2026-11-23T04:30:00Z")),
            "open, closes in 30m"
        );
    }

    #[test]
    fn a_schedule_without_a_zone_is_refused_rather_than_guessed() {
        let err = Schedule::from_parts(&[], &["03:00-05:00".into()], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs `tz`"), "{err}");
        let err: Result<Schedule, _> = toml::from_str::<RawSchedule>(r#"hours = ["03:00-05:00"]"#)
            .unwrap()
            .try_into();
        assert!(err.is_err());
    }

    #[test]
    fn nonsense_is_refused_where_it_is_typed() {
        for (days, hours, tz, says) in [
            (vec![], vec!["25:00-26:00"], "UTC", "not a time of day"),
            (vec![], vec!["3-5"], "UTC", "not a time"),
            (vec![], vec!["03:00-03:00"], "UTC", "same minute"),
            (vec![], vec!["24:00-02:00"], "UTC", "not a time of day"),
            (vec!["funday"], vec![], "UTC", "not a day"),
            (
                vec![],
                vec!["03:00-05:00"],
                "Europe/Londn",
                "not a time zone",
            ),
            (vec![], vec![], "UTC", "always open"),
        ] {
            let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            let err = Schedule::from_parts(&strings(&days), &strings(&hours), Some(tz))
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(err.contains(says), "{days:?} {hours:?} {tz}: {err}");
        }
    }

    #[test]
    fn a_zone_reads_back_in_the_databases_spelling() {
        let s = schedule(&[], &["03:00-05:00"], "europe/london");
        assert_eq!(s.to_string(), "03:00-05:00 Europe/London");
        // And what the file said is what is written back.
        assert_eq!(s.raw().tz.as_deref(), Some("europe/london"));
    }

    #[test]
    fn nothing_given_is_no_schedule() {
        assert!(Schedule::from_parts(&[], &[], None).unwrap().is_none());
        assert!(Schedule::from_parts(&[], &[], Some("  "))
            .unwrap()
            .is_none());
    }
}
