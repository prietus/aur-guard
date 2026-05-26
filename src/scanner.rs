use crate::patterns::build_rules;
use crate::report::{self, Finding, ScanResult, Tier};
use regex::Regex;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static SUMS_RE: OnceLock<Regex> = OnceLock::new();
static SOURCE_RE: OnceLock<Regex> = OnceLock::new();

fn sums_re() -> &'static Regex {
    SUMS_RE.get_or_init(|| {
        Regex::new(r"(?ms)^\s*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_\w+)?=\(([^)]*)\)")
            .unwrap()
    })
}

fn source_re() -> &'static Regex {
    SOURCE_RE.get_or_init(|| Regex::new(r"(?ms)^\s*source(?:_\w+)?=\(([^)]*)\)").unwrap())
}

pub fn scan_file(path: &Path) -> std::io::Result<ScanResult> {
    let content = fs::read_to_string(path)?;
    Ok(scan_text(&content, path.display().to_string()))
}

pub fn scan_text(content: &str, label: String) -> ScanResult {
    let rules = build_rules();
    let mut findings = Vec::new();
    let mut lines_scanned = 0usize;

    for (idx, line) in content.lines().enumerate() {
        lines_scanned += 1;
        // We do not skip comment lines: a commented-out payload is still worth flagging.
        for rule in &rules {
            if let Some(m) = rule.regex.find(line) {
                findings.push(Finding {
                    rule_id: rule.id,
                    points: rule.points,
                    override_gate: rule.override_gate,
                    title: rule.title,
                    description: rule.description,
                    line: idx + 1,
                    snippet: truncate(m.as_str(), 240),
                });
            }
        }
    }

    findings.extend(check_skip_checksums(content));
    findings.extend(check_source_array(content));

    // Highest-impact findings first; override-gate before non-gate at equal points.
    findings.sort_by(|a, b| {
        b.override_gate
            .cmp(&a.override_gate)
            .then(b.points.cmp(&a.points))
            .then(a.line.cmp(&b.line))
    });

    let (score, tier, gate) = report::score(&findings);

    ScanResult {
        path: label,
        findings,
        lines_scanned,
        score,
        tier,
        override_gate_fired: gate,
    }
}

/// Aggregate multiple per-package results into one synthetic ScanResult
/// (used by the pacman hook prompt). Tier is the worst across inputs;
/// score is the minimum trust observed.
pub fn aggregate(results: &[(String, ScanResult)], label: String) -> ScanResult {
    let findings: Vec<Finding> = results.iter().flat_map(|(_, r)| r.findings.clone()).collect();
    let lines_scanned = results.iter().map(|(_, r)| r.lines_scanned).sum();
    let tier = results
        .iter()
        .map(|(_, r)| r.tier)
        .max()
        .unwrap_or(Tier::Trusted);
    let score = results.iter().map(|(_, r)| r.score).min().unwrap_or(100);
    let gate = results.iter().find_map(|(_, r)| r.override_gate_fired);
    ScanResult {
        path: label,
        findings,
        lines_scanned,
        score,
        tier,
        override_gate_fired: gate,
    }
}

fn check_skip_checksums(content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for cap in sums_re().captures_iter(content) {
        let inside = &cap[1];
        let entries: Vec<&str> = inside
            .split(|c: char| c.is_whitespace() || c == ',')
            .map(|s| s.trim_matches(|c| c == '\'' || c == '"'))
            .filter(|s| !s.is_empty())
            .collect();
        if entries.is_empty() {
            continue;
        }
        let all_skip = entries.iter().all(|s| s.eq_ignore_ascii_case("SKIP"));
        if all_skip {
            let line = byte_offset_to_line(content, cap.get(0).unwrap().start());
            out.push(Finding {
                rule_id: "AG080",
                points: 50,
                override_gate: false,
                title: "All checksums are SKIP",
                description: "The PKGBUILD disables integrity verification for ALL sources. Anyone who compromises the upstream server can swap the content without makepkg noticing.",
                line,
                snippet: truncate(cap.get(0).unwrap().as_str().lines().next().unwrap_or(""), 240),
            });
        }
    }
    out
}

fn check_source_array(content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for cap in source_re().captures_iter(content) {
        let inside = &cap[1];
        let base_offset = cap.get(0).unwrap().start();
        for src_match in inside.split(|c: char| c.is_whitespace() || c == ',') {
            let s = src_match.trim_matches(|c| c == '\'' || c == '"');
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            let url_part = s.rsplit("::").next().unwrap_or(s);
            let line = byte_offset_to_line(content, base_offset);
            if url_part.starts_with("http://") || url_part.starts_with("ftp://") {
                out.push(Finding {
                    rule_id: "AG081",
                    points: 35,
                    override_gate: false,
                    title: "Source over an unencrypted channel (http/ftp)",
                    description: "A plain HTTP/FTP source can be swapped by a network intermediary. Use HTTPS or git+https. If the source only exists over HTTP, demand a strict sha256/sha512 checksum.",
                    line,
                    snippet: truncate(url_part, 240),
                });
            }
            if url_part.starts_with("git+http://") {
                out.push(Finding {
                    rule_id: "AG082",
                    points: 35,
                    override_gate: false,
                    title: "git repository over unencrypted HTTP",
                    description: "git+http does not authenticate the server. Use git+https or git+ssh.",
                    line,
                    snippet: truncate(url_part, 240),
                });
            }
        }
    }
    out
}

fn byte_offset_to_line(content: &str, offset: usize) -> usize {
    content[..offset.min(content.len())].bytes().filter(|b| *b == b'\n').count() + 1
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}
