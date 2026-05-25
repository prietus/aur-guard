use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "BAJA",
            Severity::Medium => "MEDIA",
            Severity::High => "ALTA",
            Severity::Critical => "CRÍTICA",
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

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub findings: Vec<Finding>,
    pub lines_scanned: usize,
}

impl ScanResult {
    pub fn count_by(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}
