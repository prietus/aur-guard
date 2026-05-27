//! AUR RPC v5 reputation lookups.
//!
//! Queries https://aur.archlinux.org/rpc/v5/info to retrieve maintainer and
//! engagement metadata for a package, then turns that into AG090..AG094
//! findings (orphaned, newly submitted, flagged out-of-date, low engagement,
//! maintainer-changed-since-last-seen).
//!
//! Fails open: any error (no network, bad JSON, package unknown) leaves the
//! scan untouched. The reputation layer must never break a scan.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::report::{Finding, Reputation, ScanResult};

const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const CACHE_TTL_SECS: u64 = 3600;
const NET_TIMEOUT_SECS: u64 = 3;

/// Static description of a non-regex rule. Used by `cmd rules` to list the
/// reputation rules alongside the regex-based ones.
pub struct MetaRule {
    pub id: &'static str,
    pub points: u32,
    pub override_gate: bool,
    pub title: &'static str,
    pub description: &'static str,
}

const RULES: &[MetaRule] = &[
    MetaRule {
        id: "AG090",
        points: 75,
        override_gate: false,
        title: "AUR maintainer changed since the previously seen version",
        description: "The current AUR maintainer differs from the one observed on the previous scan. Transfer-of-ownership is one of the most common supply-chain attack vectors in package ecosystems — verify the new maintainer is trusted before installing.",
    },
    MetaRule {
        id: "AG091",
        points: 40,
        override_gate: false,
        title: "Package is orphaned in AUR",
        description: "The AUR record shows no maintainer. Orphaned packages are easier to hijack: any user can adopt them and the next release ships under a new identity with little review.",
    },
    MetaRule {
        id: "AG092",
        points: 30,
        override_gate: false,
        title: "Newly submitted to AUR",
        description: "First submitted to the AUR less than 30 days ago. New packages have no track record and are over-represented in known AUR malware incidents.",
    },
    MetaRule {
        id: "AG093",
        points: 20,
        override_gate: false,
        title: "Flagged out-of-date in AUR",
        description: "The AUR community has flagged this package as out-of-date. Abandoned packages drift away from the upstream they claim to ship and are a common starting point for hijacks.",
    },
    MetaRule {
        id: "AG094",
        points: 25,
        override_gate: false,
        title: "Low community engagement",
        description: "Few users have voted on this package and overall popularity is near zero. Not malicious in isolation, but combined with newness, orphan status, or maintainer change it indicates a package very few people are auditing.",
    },
];

pub fn reputation_rules() -> &'static [MetaRule] {
    RULES
}

fn rule(id: &'static str) -> &'static MetaRule {
    RULES.iter().find(|r| r.id == id).expect("unknown reputation rule id")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AurInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Maintainer", default)]
    pub maintainer: Option<String>,
    #[serde(rename = "Submitter", default)]
    pub submitter: Option<String>,
    #[serde(rename = "NumVotes", default)]
    pub num_votes: u32,
    #[serde(rename = "Popularity", default)]
    pub popularity: f64,
    #[serde(rename = "FirstSubmitted", default)]
    pub first_submitted: i64,
    #[serde(rename = "LastModified", default)]
    pub last_modified: i64,
    #[serde(rename = "OutOfDate", default)]
    pub out_of_date: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AurResponse {
    #[serde(rename = "type")]
    response_type: String,
    #[serde(default)]
    results: Vec<AurInfo>,
}

/// `true` if the user has explicitly opted out of network access for this run.
pub fn network_disabled() -> bool {
    matches!(
        std::env::var("AUR_GUARD_OFFLINE").as_deref(),
        Ok("1" | "yes" | "true")
    )
}

fn cache_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AUR_GUARD_RPC_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Ok(u) = std::env::var("SUDO_USER") {
        return Some(PathBuf::from(format!("/home/{u}/.cache/aur-guard/rpc")));
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("aur-guard/rpc"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache/aur-guard/rpc"));
    }
    None
}

fn rpc_cache_path(pkgname: &str) -> Option<PathBuf> {
    cache_root().map(|d| d.join("info").join(format!("{pkgname}.json")))
}

fn maintainer_log_path(pkgname: &str) -> Option<PathBuf> {
    cache_root().map(|d| d.join("maintainer-history").join(format!("{pkgname}.txt")))
}

/// Fetch RPC info for `pkgname`. Uses the on-disk cache if fresh; otherwise
/// makes a network call. Returns `None` on any failure (the scan must
/// continue without reputation in that case).
pub fn fetch(pkgname: &str) -> Option<AurInfo> {
    if let Some(cached) = load_cached(pkgname) {
        return Some(cached);
    }
    let info = fetch_remote(pkgname)?;
    let _ = store_cached(pkgname, &info);
    Some(info)
}

fn load_cached(pkgname: &str) -> Option<AurInfo> {
    let path = rpc_cache_path(pkgname)?;
    let meta = fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age.as_secs() > CACHE_TTL_SECS {
        return None;
    }
    let body = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&body).ok()
}

fn store_cached(pkgname: &str, info: &AurInfo) -> std::io::Result<()> {
    let Some(path) = rpc_cache_path(pkgname) else { return Ok(()) };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string(info).map_err(std::io::Error::other)?;
    fs::write(path, body)
}

fn fetch_remote(pkgname: &str) -> Option<AurInfo> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(NET_TIMEOUT_SECS))
        .user_agent(concat!("aur-guard/", env!("CARGO_PKG_VERSION")))
        .build();
    let resp = agent
        .get(AUR_RPC_URL)
        .query("arg[]", pkgname)
        .call()
        .ok()?;
    let parsed: AurResponse = resp.into_json().ok()?;
    if parsed.response_type != "multiinfo" || parsed.results.is_empty() {
        return None;
    }
    let mut results = parsed.results;
    if let Some(pos) = results.iter().position(|r| r.name == pkgname) {
        Some(results.swap_remove(pos))
    } else {
        results.into_iter().next()
    }
}

/// Apply reputation-derived findings to a scan result and attach the
/// `Reputation` block for UI display. Recomputes score/tier afterwards so
/// AG090..AG094 contribute to the overall verdict.
pub fn apply(result: &mut ScanResult, pkgname: &str, info: &AurInfo) {
    let now = current_unix();
    let mut new_findings: Vec<Finding> = Vec::new();

    if info.maintainer.is_none() {
        new_findings.push(meta_finding(
            "AG091",
            "(no Maintainer in AUR record)".to_string(),
        ));
    }

    let age_days = (now - info.first_submitted).max(0) / 86_400;
    if info.first_submitted > 0 && age_days < 30 {
        new_findings.push(meta_finding(
            "AG092",
            format!("FirstSubmitted: {age_days} day(s) ago"),
        ));
    }

    if let Some(ts) = info.out_of_date {
        let ood_days = (now - ts).max(0) / 86_400;
        new_findings.push(meta_finding(
            "AG093",
            format!("flagged out-of-date {ood_days} day(s) ago"),
        ));
    }

    if info.num_votes < 5 && info.popularity < 0.1 {
        new_findings.push(meta_finding(
            "AG094",
            format!("votes={} popularity={:.3}", info.num_votes, info.popularity),
        ));
    }

    // AG090 — maintainer transfer detection. Only fires when we have a
    // recorded previous maintainer that differs from the current one. We
    // always append the current maintainer to the log so a future scan can
    // notice the change.
    if let Some(current_m) = &info.maintainer {
        if let Some(history) = load_maintainer_history(pkgname) {
            if let Some(last) = history.last() {
                if last != current_m {
                    new_findings.push(meta_finding(
                        "AG090",
                        format!("previous={last} → current={current_m}"),
                    ));
                }
            }
        }
        let _ = append_maintainer_history(pkgname, current_m);
    }

    if !new_findings.is_empty() {
        result.findings.extend(new_findings);
        // Reuse the scanner's canonical ordering so AUR findings land in the
        // right place relative to regex/metadata findings.
        crate::scanner::sort_findings(&mut result.findings);
        let (s, t, g) = crate::report::score(&result.findings);
        result.score = s;
        result.tier = t;
        result.override_gate_fired = g;
    }

    result.reputation = Some(Reputation {
        maintainer: info.maintainer.clone(),
        first_submitted: info.first_submitted,
        last_modified: info.last_modified,
        num_votes: info.num_votes,
        popularity: info.popularity,
        out_of_date: info.out_of_date,
    });
}

fn meta_finding(id: &'static str, snippet: String) -> Finding {
    let r = rule(id);
    Finding {
        rule_id: r.id,
        points: r.points,
        override_gate: r.override_gate,
        title: r.title,
        description: r.description,
        line: 0,
        snippet,
        source_file: Some("AUR".to_string()),
        is_new: false,
    }
}

fn current_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_maintainer_history(pkgname: &str) -> Option<Vec<String>> {
    let path = maintainer_log_path(pkgname)?;
    let body = fs::read_to_string(path).ok()?;
    let v: Vec<String> = body
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

fn append_maintainer_history(pkgname: &str, maintainer: &str) -> std::io::Result<()> {
    let Some(path) = maintainer_log_path(pkgname) else { return Ok(()) };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Skip if the last entry already matches — keeps the log compact.
    let history = load_maintainer_history(pkgname).unwrap_or_default();
    if history.last().map(String::as_str) == Some(maintainer) {
        return Ok(());
    }
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{maintainer}")
}
