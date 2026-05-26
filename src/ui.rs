use crate::report::ScanResult;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, IsTerminal, Write};

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
        eprintln!("    {dim}line {}:{reset} {}", f.line, f.snippet.trim());
        eprintln!("    {}", f.description);
        eprintln!();
    }
}

/// Asks for confirmation over /dev/tty so the prompt works even when stdin/stdout
/// are redirected (typical when invoked from a pacman hook or makepkg wrapper).
pub fn confirm_continue(result: &ScanResult) -> bool {
    let prompt = format!(
        "aur-guard :: tier {} (trust {}/100), {} finding(s). Continue with the install? [y/N] ",
        result.tier.label(),
        result.score,
        result.findings.len(),
    );

    // Try opening /dev/tty so we can talk to the user even when pacman/makepkg
    // have captured stdin/stdout.
    if let (Ok(mut tty_out), Ok(tty_in)) = (
        OpenOptions::new().write(true).open("/dev/tty"),
        OpenOptions::new().read(true).open("/dev/tty"),
    ) {
        let _ = tty_out.write_all(prompt.as_bytes());
        let _ = tty_out.flush();
        let mut reader = BufReader::new(tty_in);
        let mut buf = String::new();
        if reader.read_line(&mut buf).is_ok() {
            return is_yes(&buf);
        }
    }

    // Fallback: stdin/stderr if /dev/tty is not available.
    if std::io::stdin().is_terminal() {
        eprint!("{}", prompt);
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        if std::io::stdin().read_line(&mut buf).is_ok() {
            return is_yes(&buf);
        }
    }

    // No TTY: block by default. Safe choice.
    eprintln!("aur-guard :: no interactive TTY; blocking by default.");
    eprintln!(
        "             Set AUR_GUARD_ASSUME=yes only if you are absolutely sure you want to continue."
    );
    matches!(
        std::env::var("AUR_GUARD_ASSUME").as_deref(),
        Ok("yes" | "y" | "1")
    )
}

fn is_yes(input: &str) -> bool {
    let t = input.trim().to_lowercase();
    matches!(t.as_str(), "y" | "yes")
}

pub fn append_log(path: &str, result: &ScanResult) {
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let ts = unix_timestamp();
    let gate = result.override_gate_fired.unwrap_or("-");
    let promoted = result.promoted_by_diff.as_deref().unwrap_or("-");
    let _ = writeln!(
        f,
        "{ts} target={} lines={} tier={} score={} findings={} gate={} promoted={:?}",
        result.path,
        result.lines_scanned,
        result.tier.label(),
        result.score,
        result.findings.len(),
        gate,
        promoted,
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

