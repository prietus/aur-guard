use crate::report::{ScanResult, Severity};
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
        "{bold}aur-guard{reset} {dim}::{reset} {}  {dim}({} líneas){reset}",
        result.path, result.lines_scanned
    );

    if result.is_clean() {
        eprintln!("  {green}✓ Sin hallazgos.{reset}");
        return;
    }

    let crit = result.count_by(Severity::Critical);
    let high = result.count_by(Severity::High);
    let med = result.count_by(Severity::Medium);
    let low = result.count_by(Severity::Low);
    eprintln!(
        "  {} hallazgo(s):  crítica={crit}  alta={high}  media={med}  baja={low}",
        result.findings.len()
    );
    eprintln!();

    for f in &result.findings {
        let sev_color = if color { f.severity.color() } else { "" };
        eprintln!(
            "  {}  {bold}{}{reset}  {dim}[{}]{reset}",
            paint(color, sev_color, &format!("[{}]", f.severity.label())),
            f.title,
            f.rule_id
        );
        eprintln!("    {dim}línea {}:{reset} {}", f.line, f.snippet.trim());
        eprintln!("    {}", f.description);
        eprintln!();
    }
}

/// Pregunta interactiva por /dev/tty para que funcione aunque stdin/stdout vengan redirigidos
/// (típico cuando nos invocan desde un hook de pacman o un wrapper de makepkg).
pub fn confirm_continue(result: &ScanResult) -> bool {
    let crit = result.count_by(Severity::Critical);
    let high = result.count_by(Severity::High);
    let med = result.count_by(Severity::Medium);

    let prompt = format!(
        "aur-guard :: {crit} crítica / {high} alta / {med} media. ¿Continuar con la instalación? [y/N] "
    );

    // Intenta abrir /dev/tty para forzar diálogo con el usuario aunque pacman/makepkg
    // tengan stdin/stdout capturados.
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

    // Fallback: stdin/stderr si /dev/tty no está disponible.
    if std::io::stdin().is_terminal() {
        eprint!("{}", prompt);
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        if std::io::stdin().read_line(&mut buf).is_ok() {
            return is_yes(&buf);
        }
    }

    // Sin TTY: por defecto bloquear. Es lo seguro.
    eprintln!("aur-guard :: sin TTY interactivo; bloqueando por defecto.");
    eprintln!(
        "             Establezca AUR_GUARD_ASSUME=yes solo si está totalmente seguro de continuar."
    );
    matches!(
        std::env::var("AUR_GUARD_ASSUME").as_deref(),
        Ok("yes" | "y" | "1" | "si" | "sí")
    )
}

fn is_yes(input: &str) -> bool {
    let t = input.trim().to_lowercase();
    matches!(t.as_str(), "y" | "yes" | "s" | "si" | "sí")
}

pub fn append_log(path: &str, result: &ScanResult) {
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let ts = chrono_like_now();
    let _ = writeln!(
        f,
        "{ts} target={} lines={} findings={} crit={} high={} med={} low={}",
        result.path,
        result.lines_scanned,
        result.findings.len(),
        result.count_by(Severity::Critical),
        result.count_by(Severity::High),
        result.count_by(Severity::Medium),
        result.count_by(Severity::Low),
    );
    for x in &result.findings {
        let _ = writeln!(
            f,
            "{ts}   [{}] {} line={} snippet={:?}",
            x.severity.label(),
            x.rule_id,
            x.line,
            x.snippet
        );
    }
}

// Pequeño helper para no añadir la dependencia `chrono` solo para un timestamp en el log.
fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("[{}]", secs)
}
