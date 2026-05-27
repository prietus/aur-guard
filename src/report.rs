use std::cmp::Ordering;

/// Display label for a single finding. Derived from a finding's points; not
/// used for the overall block/allow decision (that's the `Tier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_points(points: u32, override_gate: bool) -> Self {
        // Override-gate rules are always "Critical" regardless of points —
        // they alone are enough to fail a build.
        if override_gate {
            return Severity::Critical;
        }
        match points {
            80..=u32::MAX => Severity::Critical,
            60..=79 => Severity::High,
            30..=59 => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        }
    }

    pub fn color(self) -> &'static str {
        match self {
            Severity::Low => "\x1b[36m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[31m",
            Severity::Critical => "\x1b[1;91m",
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Overall trust verdict for a scanned PKGBUILD. Higher is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Trusted,
    Ok,
    Sketchy,
    Suspicious,
    Malicious,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Trusted => "TRUSTED",
            Tier::Ok => "OK",
            Tier::Sketchy => "SKETCHY",
            Tier::Suspicious => "SUSPICIOUS",
            Tier::Malicious => "MALICIOUS",
        }
    }

    pub fn color(self) -> &'static str {
        match self {
            Tier::Trusted => "\x1b[1;32m",
            Tier::Ok => "\x1b[32m",
            Tier::Sketchy => "\x1b[33m",
            Tier::Suspicious => "\x1b[31m",
            Tier::Malicious => "\x1b[1;91m",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trusted" => Some(Tier::Trusted),
            "ok" => Some(Tier::Ok),
            "sketchy" => Some(Tier::Sketchy),
            "suspicious" => Some(Tier::Suspicious),
            "malicious" => Some(Tier::Malicious),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub points: u32,
    pub override_gate: bool,
    pub title: &'static str,
    pub description: &'static str,
    pub line: usize,
    pub snippet: String,
    /// File this finding came from. `None` = the PKGBUILD itself.
    /// `Some("foo.install")` = a scriptlet adjacent to the PKGBUILD.
    pub source_file: Option<String>,
    /// True if the line containing this finding did not exist in the previously
    /// cached version of the file. Set by the diff layer.
    pub is_new: bool,
}

impl Finding {
    pub fn severity(&self) -> Severity {
        Severity::from_points(self.points, self.override_gate)
    }
}

/// Aggregate of every package an AUR maintainer is responsible for. Used
/// to decide whether they look "established" enough to suppress the
/// per-package newness / low-engagement flags.
#[derive(Debug, Clone)]
pub struct MaintainerSummary {
    pub package_count: u32,
    pub total_votes: u32,
    /// Unix timestamp of the oldest package by this maintainer (i.e. when
    /// they first published anything to AUR). 0 if unknown.
    pub oldest_first_submitted: i64,
}

/// AUR community/reputation snapshot, attached when a scan succeeds in
/// retrieving RPC info for the package. Purely informational; the actual
/// rule decisions live as AG09x findings.
#[derive(Debug, Clone)]
pub struct Reputation {
    pub maintainer: Option<String>,
    pub first_submitted: i64,
    pub last_modified: i64,
    pub num_votes: u32,
    pub popularity: f64,
    pub out_of_date: Option<i64>,
    /// True when the maintainer's overall AUR track record clears the
    /// "established" threshold (see `rpc::is_established`). In that case
    /// AG092 (newly submitted) and AG094 (low engagement) are suppressed
    /// for *this* package, since they only meaningfully fire on accounts
    /// with no history.
    pub maintainer_established: bool,
    /// Per-maintainer aggregate (oldest package age, total packages, total
    /// votes) used both for the establishment check and for the banner
    /// context line.
    pub maintainer_summary: Option<MaintainerSummary>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub findings: Vec<Finding>,
    pub lines_scanned: usize,
    /// 0..=100. 100 = pristine, 0 = maximum risk. Always set by `score()`.
    pub score: u32,
    pub tier: Tier,
    /// rule_id of the first override-gate finding, if any.
    pub override_gate_fired: Option<&'static str>,
    /// Set when the diff layer promoted the tier because of a newly-introduced
    /// finding. Holds a short human-readable explanation.
    pub promoted_by_diff: Option<String>,
    /// AUR RPC snapshot — `None` if no lookup happened (offline, package not
    /// in AUR, network failure).
    pub reputation: Option<Reputation>,
}

impl ScanResult {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Compute trust score (0..=100, higher = better) and tier from a list of findings.
///
/// Algorithm:
///   - If any finding has `override_gate = true`, tier is forced to `Malicious`
///     and score is 0 (one critical pattern alone is enough).
///   - Otherwise, total risk = sum(points), capped at 100. trust = 100 - risk.
///   - Tier thresholds (on trust):
///       Trusted:    trust >= 90
///       Ok:         trust >= 70
///       Sketchy:    trust >= 50
///       Suspicious: trust >= 25
///       Malicious:  trust <  25
pub fn score(findings: &[Finding]) -> (u32, Tier, Option<&'static str>) {
    let gate = findings.iter().find(|f| f.override_gate).map(|f| f.rule_id);
    if let Some(id) = gate {
        return (0, Tier::Malicious, Some(id));
    }
    let risk: u32 = findings.iter().map(|f| f.points).sum::<u32>().min(100);
    let trust = 100 - risk;
    let tier = match trust {
        90..=u32::MAX => Tier::Trusted,
        70..=89 => Tier::Ok,
        50..=69 => Tier::Sketchy,
        25..=49 => Tier::Suspicious,
        _ => Tier::Malicious,
    };
    (trust, tier, None)
}
