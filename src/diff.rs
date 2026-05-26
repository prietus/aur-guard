//! PKGBUILD history cache + supply-chain diff.
//!
//! For every package we successfully scan, we cache the PKGBUILD content under
//! `$XDG_CACHE_HOME/aur-guard/pkgbuild-history/<pkgname>.txt`. On subsequent
//! scans we compare the current content against the cached one and mark
//! findings that land on **newly-introduced lines** — those are much stronger
//! signal than the mere presence of a pattern.
//!
//! The escalation policy:
//!   * any *new* finding with points ≥ 80 → tier promoted to `Malicious`
//!     (supply-chain attacker just added an unambiguous payload)
//!   * any *new* finding with points ≥ 60 → tier promoted to at least `Suspicious`
//!   * low-point new findings do not promote (legitimate package churn)

use crate::report::{Finding, ScanResult, Tier};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

static PKGNAME_RE: OnceLock<Regex> = OnceLock::new();
static PKGBASE_RE: OnceLock<Regex> = OnceLock::new();

fn pkgname_re() -> &'static Regex {
    PKGNAME_RE.get_or_init(|| {
        // pkgname=foo  OR  pkgname=(foo bar baz)  — take the first identifier.
        Regex::new(r#"(?m)^\s*pkgname\s*=\s*\(?\s*['"]?([A-Za-z0-9._+@-]+)"#).unwrap()
    })
}

fn pkgbase_re() -> &'static Regex {
    PKGBASE_RE.get_or_init(|| {
        Regex::new(r#"(?m)^\s*pkgbase\s*=\s*['"]?([A-Za-z0-9._+@-]+)"#).unwrap()
    })
}

/// Extract the package identifier from a PKGBUILD: `pkgbase` if set, otherwise
/// the first `pkgname`. Used as the cache key.
pub fn pkgname_from(content: &str) -> Option<String> {
    if let Some(c) = pkgbase_re().captures(content) {
        return Some(c[1].to_string());
    }
    pkgname_re().captures(content).map(|c| c[1].to_string())
}

/// Directory where per-package history is cached. Honours `SUDO_USER` so that
/// when the pacman hook runs as root we still write into the invoking user's
/// cache (and read the same file back next time).
fn cache_dir() -> Option<PathBuf> {
    // 1) Explicit override.
    if let Ok(p) = std::env::var("AUR_GUARD_HISTORY_DIR") {
        return Some(PathBuf::from(p));
    }
    // 2) SUDO_USER's home (when running as root via the pacman hook).
    if let Ok(u) = std::env::var("SUDO_USER") {
        let p = PathBuf::from(format!("/home/{u}/.cache/aur-guard/pkgbuild-history"));
        return Some(p);
    }
    // 3) $XDG_CACHE_HOME or ~/.cache.
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("aur-guard/pkgbuild-history"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache/aur-guard/pkgbuild-history"));
    }
    None
}

fn history_path(pkgname: &str) -> Option<PathBuf> {
    cache_dir().map(|d| d.join(format!("{pkgname}.txt")))
}

pub fn load_previous(pkgname: &str) -> Option<String> {
    let path = history_path(pkgname)?;
    fs::read_to_string(path).ok()
}

pub fn save_current(pkgname: &str, content: &str) -> io::Result<()> {
    let Some(path) = history_path(pkgname) else {
        return Ok(()); // no cache dir resolvable; silently skip
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

/// Mark every finding whose line text is absent from the previous version.
/// Comparison is on trimmed line content, so reformatting noise doesn't trip
/// false "new" markers but real content additions do.
pub fn mark_new_findings(findings: &mut [Finding], previous: &str, current: &str) {
    let prev_set: HashSet<&str> = previous.lines().map(|l| l.trim()).collect();
    let cur_lines: Vec<&str> = current.lines().collect();
    for f in findings.iter_mut() {
        // Only diff findings that came from the PKGBUILD itself (source_file is
        // None). .install scriptlets get their own diff treatment later.
        if f.source_file.is_some() {
            continue;
        }
        let Some(line_text) = cur_lines.get(f.line.saturating_sub(1)) else { continue };
        let trimmed = line_text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !prev_set.contains(trimmed) {
            f.is_new = true;
        }
    }
}

/// Apply the diff-based escalation policy in place.
pub fn escalate_tier(result: &mut ScanResult) {
    // Find the new finding that justifies the strongest promotion.
    let mut best: Option<&Finding> = None;
    for f in &result.findings {
        if !f.is_new {
            continue;
        }
        if best.map(|b| f.points > b.points).unwrap_or(true) {
            best = Some(f);
        }
    }
    let Some(f) = best else { return };

    let target = if f.points >= 80 {
        Tier::Malicious
    } else if f.points >= 60 {
        Tier::Suspicious
    } else {
        return;
    };

    if result.tier >= target {
        return; // already at or above the promotion target
    }

    result.tier = target;
    if target == Tier::Malicious {
        result.score = 0;
        // Record the diff promotion so the UI can show the reason. We don't
        // overwrite override_gate_fired — that field is specifically for
        // gate rules; diff promotion has its own field.
    }
    result.promoted_by_diff = Some(format!(
        "newly-introduced finding {} ({} pts) — promoted to {}",
        f.rule_id,
        f.points,
        target.label(),
    ));
}
