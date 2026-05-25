use crate::patterns::build_rules;
use crate::report::{Finding, ScanResult, Severity};
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
        // No saltamos comentarios: un PKGBUILD comentado con un payload sigue siendo señal de alerta.
        for rule in &rules {
            if let Some(m) = rule.regex.find(line) {
                findings.push(Finding {
                    rule_id: rule.id,
                    severity: rule.severity,
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

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));

    ScanResult {
        path: label,
        findings,
        lines_scanned,
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
                severity: Severity::High,
                title: "Todas las sumas de verificación son SKIP",
                description: "El PKGBUILD desactiva la verificación de integridad de TODAS las fuentes. Cualquiera que comprometa el servidor de origen puede sustituir el contenido sin que makepkg lo detecte.",
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
                    severity: Severity::Medium,
                    title: "Fuente sobre canal sin cifrar (http/ftp)",
                    description: "Una fuente HTTP/FTP plana puede ser sustituida por un intermediario. Use HTTPS o git+https. Si la fuente solo existe en HTTP, exija sha256/sha512 estricto.",
                    line,
                    snippet: truncate(url_part, 240),
                });
            }
            if url_part.starts_with("git+http://") {
                out.push(Finding {
                    rule_id: "AG082",
                    severity: Severity::Medium,
                    title: "Repositorio git sobre HTTP sin cifrar",
                    description: "git+http no autentica al servidor. Use git+https o git+ssh.",
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
