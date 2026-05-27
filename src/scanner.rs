use crate::patterns::build_rules;
use crate::report::{self, Finding, ScanResult, Tier};
use crate::rpc::MetaRule;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Non-regex rules implemented as dedicated `check_*` functions below.
/// Listed here so `aur-guard rules` can surface them alongside the regex
/// rule set. Keep in lockstep with the actual checks.
pub fn metadata_rules() -> &'static [MetaRule] {
    const META: &[MetaRule] = &[
        MetaRule {
            id: "AG080",
            points: 50,
            override_gate: false,
            title: "All checksums are SKIP",
            description: "The PKGBUILD disables integrity verification for ALL sources.",
        },
        MetaRule {
            id: "AG081",
            points: 35,
            override_gate: false,
            title: "Source over an unencrypted channel (http/ftp)",
            description: "A plain HTTP/FTP source can be swapped by a network intermediary.",
        },
        MetaRule {
            id: "AG082",
            points: 35,
            override_gate: false,
            title: "git repository over unencrypted HTTP",
            description: "git+http does not authenticate the server.",
        },
        MetaRule {
            id: "AG083",
            points: 50,
            override_gate: false,
            title: "Source domain does not match declared upstream URL",
            description: "Classic impersonation pattern in malicious -bin packages.",
        },
    ];
    META
}

static SUMS_RE: OnceLock<Regex> = OnceLock::new();
static SOURCE_RE: OnceLock<Regex> = OnceLock::new();
static URL_RE: OnceLock<Regex> = OnceLock::new();

fn sums_re() -> &'static Regex {
    SUMS_RE.get_or_init(|| {
        Regex::new(r"(?ms)^\s*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_\w+)?=\(([^)]*)\)")
            .unwrap()
    })
}

fn source_re() -> &'static Regex {
    SOURCE_RE.get_or_init(|| Regex::new(r"(?ms)^\s*source(?:_\w+)?=\(([^)]*)\)").unwrap())
}

fn url_re() -> &'static Regex {
    URL_RE.get_or_init(|| {
        Regex::new(r#"(?m)^\s*url\s*=\s*["']?(https?://[^\s"'`]+)["']?"#).unwrap()
    })
}

/// Scan a PKGBUILD and every adjacent `*.install` scriptlet in the same
/// directory. All findings roll up into a single ScanResult so the tier/score
/// reflects the package as a whole, not just the PKGBUILD in isolation.
pub fn scan_pkgbuild_bundle(pkgbuild: &Path) -> std::io::Result<ScanResult> {
    let pkgbuild_content = fs::read_to_string(pkgbuild)?;
    let mut combined = scan_text(&pkgbuild_content, pkgbuild.display().to_string());

    let dir = pkgbuild.parent().unwrap_or(Path::new("."));
    let mut install_files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|s| s.to_str()) == Some("install")
                    && p.is_file()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    install_files.sort();

    for ifile in &install_files {
        let Ok(content) = fs::read_to_string(ifile) else { continue };
        let name = ifile
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?.install")
            .to_string();
        let sub = scan_text(&content, format!("{} :: {}", combined.path, name));
        combined.lines_scanned += sub.lines_scanned;
        for mut f in sub.findings {
            f.source_file = Some(name.clone());
            combined.findings.push(f);
        }
    }

    // Re-sort all findings together and recompute score across the bundle.
    sort_findings(&mut combined.findings);
    let (s, t, g) = report::score(&combined.findings);
    combined.score = s;
    combined.tier = t;
    combined.override_gate_fired = g;
    Ok(combined)
}

pub fn scan_text(content: &str, label: String) -> ScanResult {
    let rules = build_rules();
    let mut findings = Vec::new();
    let mut lines_scanned = 0usize;

    for (idx, line) in content.lines().enumerate() {
        lines_scanned += 1;
        // We do not skip comment lines: a commented-out payload is still worth flagging.
        for rule in &rules {
            if rule.regex.is_match(line) {
                // Snippet is the full source line (trimmed + truncated) rather
                // than just the regex match. Gives the user enough context to
                // tell at a glance whether the hit is a real command or e.g. a
                // help-text mention inside a heredoc.
                findings.push(Finding {
                    rule_id: rule.id,
                    points: rule.points,
                    override_gate: rule.override_gate,
                    title: rule.title,
                    description: rule.description,
                    line: idx + 1,
                    snippet: truncate(line.trim(), 240),
                    source_file: None,
                    is_new: false,
                });
            }
        }
    }

    findings.extend(check_skip_checksums(content));
    findings.extend(check_source_array(content));
    findings.extend(check_url_vs_sources(content));

    sort_findings(&mut findings);

    let (score, tier, gate) = report::score(&findings);

    ScanResult {
        path: label,
        findings,
        lines_scanned,
        score,
        tier,
        override_gate_fired: gate,
        promoted_by_diff: None,
        reputation: None,
    }
}

pub(crate) fn sort_findings(findings: &mut [Finding]) {
    // Highest-impact findings first; new findings boosted to the top within
    // a tier so supply-chain changes are visible immediately.
    findings.sort_by(|a, b| {
        b.override_gate
            .cmp(&a.override_gate)
            .then(b.is_new.cmp(&a.is_new))
            .then(b.points.cmp(&a.points))
            .then(a.line.cmp(&b.line))
    });
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
    let promoted = results.iter().find_map(|(_, r)| r.promoted_by_diff.clone());
    ScanResult {
        path: label,
        findings,
        lines_scanned,
        score,
        tier,
        override_gate_fired: gate,
        promoted_by_diff: promoted,
        reputation: None,
    }
}

fn check_skip_checksums(content: &str) -> Vec<Finding> {
    // Fire at most once per scan: even when several `sha256sums_<arch>=` arrays
    // are all-SKIP, "integrity verification is disabled" is a single property
    // of the PKGBUILD, not something that compounds per architecture.
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
        if entries.iter().all(|s| s.eq_ignore_ascii_case("SKIP")) {
            let line = byte_offset_to_line(content, cap.get(0).unwrap().start());
            return vec![Finding {
                rule_id: "AG080",
                points: 50,
                override_gate: false,
                title: "All checksums are SKIP",
                description: "The PKGBUILD disables integrity verification for ALL sources. Anyone who compromises the upstream server can swap the content without makepkg noticing.",
                line,
                snippet: truncate(
                    cap.get(0).unwrap().as_str().lines().next().unwrap_or(""),
                    240,
                ),
                source_file: None,
                is_new: false,
            }];
        }
    }
    Vec::new()
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
                    source_file: None,
                    is_new: false,
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
                    source_file: None,
                    is_new: false,
                });
            }
        }
    }
    out
}

/// AG083 — declared upstream (`url=`) does not match the domain of one or
/// more `source=()` entries. Catches fork impersonation typical of malicious
/// `-bin` packages that point at an attacker-controlled mirror.
fn check_url_vs_sources(content: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    let Some(url_cap) = url_re().captures(content) else {
        return out;
    };
    let upstream_url = url_cap.get(1).unwrap().as_str();
    let Some(upstream_ident) = source_identity(upstream_url) else {
        return out;
    };

    for cap in source_re().captures_iter(content) {
        let inside = &cap[1];
        let base_offset = cap.get(0).unwrap().start();
        for src_match in inside.split(|c: char| c.is_whitespace() || c == ',') {
            let s = src_match.trim_matches(|c| c == '\'' || c == '"');
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            let url_part = s.rsplit("::").next().unwrap_or(s);
            // Strip VCS prefixes like git+https://, svn+https://, hg+http://, bzr+, etc.
            let stripped = strip_vcs_prefix(url_part);
            if !(stripped.starts_with("http://") || stripped.starts_with("https://")) {
                continue;
            }
            let Some(src_ident) = source_identity(stripped) else { continue };
            if src_ident != upstream_ident {
                let line = byte_offset_to_line(content, base_offset);
                out.push(Finding {
                    rule_id: "AG083",
                    points: 50,
                    override_gate: false,
                    title: "Source domain does not match declared upstream URL",
                    description: "The `url=` field points at one project, but a `source=` entry downloads from a different domain (or GitHub organisation). Classic impersonation pattern in malicious -bin packages — verify that the source really belongs to the project named by `url=`.",
                    line,
                    snippet: truncate(&format!("source={url_part}  vs  url={upstream_url}"), 240),
                    source_file: None,
                    is_new: false,
                });
            }
        }
    }
    out
}

/// "Identity" of a URL for cross-check purposes:
///   - `github.com/<org>/...`  → `github.com/<org>` (org-level comparison)
///   - `<host>/...`            → `<registered-domain>` (eTLD+1, naive)
fn source_identity(url: &str) -> Option<String> {
    // host = between scheme and first '/' (or end)
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (host_with_port, path) = match after_scheme.split_once('/') {
        Some((h, p)) => (h, p),
        None => (after_scheme, ""),
    };
    let host = host_with_port.split(':').next().unwrap_or(host_with_port).to_lowercase();
    if host.is_empty() {
        return None;
    }

    // GitHub / GitLab / Codeberg / Bitbucket: include the first path segment
    // (the organisation) in the identity so a different org on the same forge
    // is a mismatch.
    const FORGES: &[&str] = &["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"];
    if FORGES.iter().any(|f| host == *f) {
        let org = path.split('/').next().unwrap_or("").to_lowercase();
        if org.is_empty() {
            return Some(host);
        }
        return Some(format!("{host}/{org}"));
    }

    // Otherwise, naive eTLD+1: last two dotted segments.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        return Some(host);
    }
    Some(format!(
        "{}.{}",
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    ))
}

fn strip_vcs_prefix(s: &str) -> &str {
    for prefix in &["git+", "svn+", "hg+", "bzr+", "fossil+"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest;
        }
    }
    s
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
