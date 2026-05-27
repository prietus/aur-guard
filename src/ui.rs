use crate::report::{Reputation, ScanResult};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn use_color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Best-effort terminal width. Pacman/yay set `COLUMNS` for their hooks; we
/// fall back to 100 columns when nothing is available, which renders fine
/// in both interactive terminals and pacman's captured output.
fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|w| *w >= 40)
        .unwrap_or(100)
}

/// Char-boundary-aware truncation with an ellipsis. `…` counts as one char.
fn truncate_display(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let take = max.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

/// Word-wrap a paragraph at `width` columns, prefixing every line with
/// `indent`. Long single tokens (URLs, base64) that overflow the width are
/// placed on their own line and then truncated to `width` so we never spill
/// across the terminal.
fn wrap_paragraph(text: &str, width: usize, indent: &str) -> String {
    let indent_len = indent.chars().count();
    let max_content = width.saturating_sub(indent_len).max(20);
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in text.split_whitespace() {
        let w_len = word.chars().count();
        let candidate_len = if current_len == 0 { w_len } else { current_len + 1 + w_len };
        if current_len > 0 && candidate_len > max_content {
            lines.push(format!("{indent}{current}"));
            current.clear();
            current_len = 0;
        }
        if current_len > 0 {
            current.push(' ');
            current_len += 1;
        }
        if w_len > max_content {
            current.push_str(&truncate_display(word, max_content));
            current_len = max_content;
        } else {
            current.push_str(word);
            current_len += w_len;
        }
    }
    if !current.is_empty() {
        lines.push(format!("{indent}{current}"));
    }
    lines.join("\n")
}

pub fn print_result(result: &ScanResult, color: bool) {
    let bold = if color { "\x1b[1m" } else { "" };
    let dim = if color { "\x1b[2m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let green = if color { "\x1b[32m" } else { "" };

    eprintln!(
        "{bold}aur-guard{reset} {dim}::{reset} {}  {dim}({} lines){reset}",
        result.path, result.lines_scanned
    );

    let tier_label = paint(color, result.tier.color(), &format!("[{}]", result.tier.label()));
    eprintln!(
        "  {tier_label} {bold}trust score {}/100{reset}",
        result.score
    );
    if let Some(gate_id) = result.override_gate_fired {
        eprintln!(
            "  {dim}→ override gate fired ({}) — one match is enough to fail the build{reset}",
            gate_id
        );
    }
    if let Some(reason) = &result.promoted_by_diff {
        let yellow = if color { "\x1b[33m" } else { "" };
        eprintln!(
            "  {yellow}→ supply-chain diff: {}{reset}",
            reason
        );
    }
    if let Some(rep) = &result.reputation {
        let cyan = if color { "\x1b[36m" } else { "" };
        eprintln!("  {cyan}→ AUR: {}{reset}", format_reputation(rep));
        if let Some(line) = format_maintainer_track_record(rep) {
            eprintln!("  {dim}  {line}{reset}");
        }
    }

    if result.is_clean() {
        eprintln!("  {green}✓ No findings.{reset}");
        return;
    }

    let new_count = result.findings.iter().filter(|f| f.is_new).count();
    if new_count > 0 {
        let yellow = if color { "\x1b[33m" } else { "" };
        eprintln!(
            "  {} finding(s), {yellow}{new_count} new since the previous version{reset}:",
            result.findings.len()
        );
    } else {
        eprintln!("  {} finding(s):", result.findings.len());
    }
    eprintln!();

    let width = term_width();
    // Reserve a small margin so wrap output fits even on narrow terminals.
    let snippet_width = width.saturating_sub(14).max(40);
    let desc_width = width.saturating_sub(4).max(60);

    for f in &result.findings {
        let sev = f.severity();
        let sev_color = if color { sev.color() } else { "" };
        let gate_marker = if f.override_gate { " ⛔" } else { "" };
        let new_marker = if f.is_new {
            paint(color, "\x1b[1;33m", " [NEW]")
        } else {
            String::new()
        };
        let file_marker = match &f.source_file {
            Some(name) => format!(" {dim}[+{name}]{reset}"),
            None => String::new(),
        };
        eprintln!(
            "  {}{new_marker}  {bold}{}{reset}{file_marker}  {dim}[{} · {}pts{}]{reset}",
            paint(color, sev_color, &format!("[{}]", sev.label())),
            f.title,
            f.rule_id,
            f.points,
            gate_marker
        );
        let snippet = truncate_display(f.snippet.trim(), snippet_width);
        eprintln!("    {dim}line {}:{reset} {}", f.line, snippet);
        eprintln!("{}", wrap_paragraph(f.description, desc_width, "    "));
        eprintln!();
    }
}

/// Visually-distinct y/N prompt. Renders a horizontal rule, a labelled
/// header, the summary lines provided by the caller, and the question. The
/// whole block goes to `/dev/tty` (bypassing pacman's captured stderr) so
/// the prompt cannot get interleaved with earlier log output. Stderr is
/// flushed first to make sure preceding eprintln output is visible.
///
/// Returns `true` on yes. On non-interactive use it honours
/// `AUR_GUARD_ASSUME=yes`; otherwise it blocks by default.
pub fn confirm(label: &str, summary: &[String], question: &str) -> bool {
    let color = use_color();
    let bold = if color { "\x1b[1m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let cyan = if color { "\x1b[1;36m" } else { "" };

    let rule_width = term_width().clamp(40, 72);
    let rule = "━".repeat(rule_width);

    let mut block = String::new();
    block.push('\n');
    block.push_str(&format!("{cyan}{rule}{reset}\n"));
    block.push_str(&format!("  {bold}aur-guard :: {label}{reset}\n"));
    for line in summary {
        block.push_str(&format!("  ▸ {line}\n"));
    }
    block.push_str(&format!(
        "  ▸ {bold}{question}{reset}  [y/N] "
    ));

    // Force any previously-buffered stderr (pacman wraps us in a pipe, so
    // stderr is line-buffered to its capture) to drain before we touch the
    // terminal directly.
    let _ = std::io::stderr().flush();

    if let (Ok(mut tty_out), Ok(tty_in)) = (
        OpenOptions::new().write(true).open("/dev/tty"),
        OpenOptions::new().read(true).open("/dev/tty"),
    ) {
        let _ = tty_out.write_all(block.as_bytes());
        let _ = tty_out.flush();
        let mut reader = BufReader::new(tty_in);
        let mut buf = String::new();
        if reader.read_line(&mut buf).is_ok() {
            return is_yes(&buf);
        }
    }

    if std::io::stdin().is_terminal() {
        eprint!("{}", block);
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        if std::io::stdin().read_line(&mut buf).is_ok() {
            return is_yes(&buf);
        }
    }

    eprintln!("\naur-guard :: no interactive TTY; blocking by default.");
    eprintln!(
        "             Set AUR_GUARD_ASSUME=yes only if you are absolutely sure you want to continue."
    );
    matches!(
        std::env::var("AUR_GUARD_ASSUME").as_deref(),
        Ok("yes" | "y" | "1")
    )
}

/// Convenience for the makepkg shim path — a single ScanResult prompt.
pub fn confirm_build(result: &ScanResult) -> bool {
    let summary = vec![format!(
        "tier {}  (trust {}/100, {} finding(s))",
        result.tier.label(),
        result.score,
        result.findings.len()
    )];
    confirm("decision required", &summary, "continue with this build?")
}

fn is_yes(input: &str) -> bool {
    let t = input.trim().to_lowercase();
    matches!(t.as_str(), "y" | "yes")
}

fn format_reputation(rep: &Reputation) -> String {
    let m = rep.maintainer.as_deref().unwrap_or("(orphaned)");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let age = days_since(now, rep.first_submitted);
    let last = days_since(now, rep.last_modified);
    let mut out = format!(
        "maintainer={m}, age={age}d, last update={last}d ago, votes={}, popularity={:.2}",
        rep.num_votes, rep.popularity
    );
    if let Some(ts) = rep.out_of_date {
        let ood = days_since(now, ts);
        out.push_str(&format!(", ⚑ out-of-date {ood}d"));
    }
    if rep.maintainer_established {
        out.push_str(" (established maintainer)");
    }
    out
}

/// Optional second line under the AUR banner: the maintainer's overall
/// track record. Shown whenever we have a summary at all, and explicitly
/// notes the AG092/AG094 suppression when established.
fn format_maintainer_track_record(rep: &Reputation) -> Option<String> {
    let s = rep.maintainer_summary.as_ref()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let oldest_d = days_since(now, s.oldest_first_submitted);
    let mut line = format!(
        "track record: {} pkg(s) · {} vote(s) total · oldest {}d ago",
        s.package_count, s.total_votes, oldest_d
    );
    if rep.maintainer_established {
        line.push_str(" — AG092/AG094 suppressed");
    }
    Some(line)
}

fn days_since(now: i64, ts: i64) -> i64 {
    if ts <= 0 {
        return -1;
    }
    (now - ts).max(0) / 86_400
}

pub fn append_log(path: &str, result: &ScanResult) {
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let ts = unix_timestamp();
    let gate = result.override_gate_fired.unwrap_or("-");
    let promoted = result.promoted_by_diff.as_deref().unwrap_or("-");
    let rep = result
        .reputation
        .as_ref()
        .map(format_reputation)
        .unwrap_or_else(|| "-".to_string());
    let _ = writeln!(
        f,
        "{ts} target={} lines={} tier={} score={} findings={} gate={} promoted={:?} aur={:?}",
        result.path,
        result.lines_scanned,
        result.tier.label(),
        result.score,
        result.findings.len(),
        gate,
        promoted,
        rep,
    );
    for x in &result.findings {
        let src = x.source_file.as_deref().unwrap_or("PKGBUILD");
        let _ = writeln!(
            f,
            "{ts}   [{}] {} points={} gate={} new={} src={} line={} snippet={:?}",
            x.severity().label(),
            x.rule_id,
            x.points,
            x.override_gate,
            x.is_new,
            src,
            x.line,
            x.snippet
        );
    }
}

// Small helper so we don't pull in `chrono` just to print a log timestamp.
fn unix_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("[{}]", secs)
}

