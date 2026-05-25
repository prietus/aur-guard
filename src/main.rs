mod patterns;
mod report;
mod scanner;
mod ui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::report::{ScanResult, Severity};

const LOG_PATH: &str = "/var/log/aur-guard.log";
const FALLBACK_LOG: &str = "/tmp/aur-guard.log";

#[derive(Parser)]
#[command(
    name = "aur-guard",
    version,
    about = "Security scanner for AUR PKGBUILDs.",
    long_about = "aur-guard scans a PKGBUILD for common malicious patterns \
                  (curl|bash, reverse shells, writes to authorized_keys, sudo, \
                  suid, ...) and blocks with interactive confirmation."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a PKGBUILD (or any file) and print findings.
    Scan {
        /// Path to the PKGBUILD. If it is a directory, looks for PKGBUILD inside.
        path: PathBuf,
        /// No colors or decoration.
        #[arg(long)]
        plain: bool,
    },
    /// Same as `scan` but the exit code reflects the result (0 clean, 2 with findings).
    Check {
        path: PathBuf,
        #[arg(long)]
        plain: bool,
        /// Minimum severity that triggers a non-zero exit (low|medium|high|critical).
        #[arg(long, default_value = "high")]
        threshold: String,
    },
    /// makepkg wrapper: scan the PKGBUILD in the cwd and, if there are findings,
    /// ask for interactive confirmation. On accept, exec the real makepkg with the
    /// given arguments.
    MakepkgWrap {
        /// Path to the real makepkg binary.
        #[arg(long, default_value = "/usr/bin/makepkg", env = "AUR_GUARD_REAL_MAKEPKG")]
        real: PathBuf,
        /// Arguments forwarded to makepkg.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// pacman hook: read target packages from stdin (one per line), locate the
    /// PKGBUILD in known AUR-helper caches, and warn / block on findings.
    PacmanHook,
    /// List every active detection rule.
    Rules,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aur-guard: error: {e:#}");
            ExitCode::from(127)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Scan { path, plain } => cmd_scan(path, plain),
        Cmd::Check { path, plain, threshold } => cmd_check(path, plain, &threshold),
        Cmd::MakepkgWrap { real, args } => cmd_makepkg_wrap(real, args),
        Cmd::PacmanHook => cmd_pacman_hook(),
        Cmd::Rules => cmd_rules(),
    }
}

fn resolve_pkgbuild(path: &Path) -> Result<PathBuf> {
    if path.is_dir() {
        let p = path.join("PKGBUILD");
        anyhow::ensure!(p.exists(), "no PKGBUILD found in {}", path.display());
        Ok(p)
    } else {
        anyhow::ensure!(path.exists(), "path does not exist: {}", path.display());
        Ok(path.to_path_buf())
    }
}

fn cmd_scan(path: PathBuf, plain: bool) -> Result<ExitCode> {
    let path = resolve_pkgbuild(&path)?;
    let result = scanner::scan_file(&path).with_context(|| format!("reading {}", path.display()))?;
    let color = !plain && ui::use_color();
    ui::print_result(&result, color);
    Ok(if result.is_clean() {
        ExitCode::from(0)
    } else {
        ExitCode::from(2)
    })
}

fn parse_threshold(s: &str) -> Result<Severity> {
    Ok(match s.to_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" | "med" => Severity::Medium,
        "high" => Severity::High,
        "critical" | "crit" => Severity::Critical,
        other => anyhow::bail!("unknown threshold: {other}"),
    })
}

fn cmd_check(path: PathBuf, plain: bool, threshold: &str) -> Result<ExitCode> {
    let thr = parse_threshold(threshold)?;
    let path = resolve_pkgbuild(&path)?;
    let result = scanner::scan_file(&path)?;
    let color = !plain && ui::use_color();
    ui::print_result(&result, color);
    let trip = result
        .findings
        .iter()
        .any(|f| f.severity.rank() >= thr.rank());
    Ok(if trip { ExitCode::from(2) } else { ExitCode::from(0) })
}

fn cmd_makepkg_wrap(real: PathBuf, args: Vec<String>) -> Result<ExitCode> {
    let cwd = std::env::current_dir()?;
    let pkgbuild = cwd.join("PKGBUILD");

    // If there is no PKGBUILD here (e.g. `makepkg --version`), forward as-is.
    if !pkgbuild.exists() {
        return exec_real(&real, &args);
    }

    let result = scanner::scan_file(&pkgbuild)?;
    let color = ui::use_color();
    ui::print_result(&result, color);
    write_log(&result);

    if result.is_clean() {
        return exec_real(&real, &args);
    }

    let has_high_or_above = result
        .findings
        .iter()
        .any(|f| f.severity.rank() >= Severity::High.rank());

    if has_high_or_above {
        if !ui::confirm_continue(&result) {
            eprintln!("aur-guard :: install aborted by user.");
            return Ok(ExitCode::from(1));
        }
        eprintln!("aur-guard :: user confirmed; continuing.");
    } else {
        eprintln!("aur-guard :: only low-severity findings; continuing without prompt.");
    }

    exec_real(&real, &args)
}

fn cmd_pacman_hook() -> Result<ExitCode> {
    // When NeedsTargets is set, pacman sends the targets on stdin.
    let mut targets = Vec::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let t = line.trim();
        if !t.is_empty() {
            targets.push(t.to_string());
        }
    }

    if targets.is_empty() {
        eprintln!("aur-guard :: no targets received; nothing to audit.");
        return Ok(ExitCode::from(0));
    }

    let foreign = list_foreign_packages();
    let caches = collect_cache_dirs();

    let aur_targets: Vec<String> = targets
        .iter()
        .map(|p| pkg_name_only(p))
        .filter(|name| foreign.iter().any(|f| f == name))
        .collect();

    if aur_targets.is_empty() {
        eprintln!(
            "aur-guard :: {} target(s), 0 from AUR — nothing to audit.",
            targets.len()
        );
        return Ok(ExitCode::from(0));
    }

    let mut combined_findings: Vec<(String, ScanResult)> = Vec::new();
    let mut clean_count = 0usize;
    let mut missing_count = 0usize;

    for name in &aur_targets {
        if let Some(pkgbuild) = find_pkgbuild(name, &caches) {
            match scanner::scan_file(&pkgbuild) {
                Ok(r) if !r.is_clean() => combined_findings.push((name.clone(), r)),
                Ok(r) => {
                    clean_count += 1;
                    write_log(&r);
                }
                Err(e) => {
                    eprintln!("aur-guard :: error scanning {}: {e}", pkgbuild.display());
                    missing_count += 1;
                }
            }
        } else {
            eprintln!(
                "aur-guard :: AUR package \"{name}\" — PKGBUILD not found in known caches; skipping."
            );
            missing_count += 1;
        }
    }

    let color = ui::use_color();
    let mut critical_total = 0usize;
    let mut high_total = 0usize;
    for (_, r) in &combined_findings {
        ui::print_result(r, color);
        write_log(r);
        critical_total += r.count_by(Severity::Critical);
        high_total += r.count_by(Severity::High);
    }

    eprintln!(
        "aur-guard :: {} AUR target(s) — {} clean, {} skipped, {} with findings ({} critical, {} high).",
        aur_targets.len(),
        clean_count,
        missing_count,
        combined_findings.len(),
        critical_total,
        high_total
    );

    if critical_total + high_total == 0 {
        return Ok(ExitCode::from(0));
    }

    // Synthetic aggregate used only for the prompt.
    let synthetic = ScanResult {
        path: format!("{} AUR package(s)", combined_findings.len()),
        findings: combined_findings.iter().flat_map(|(_, r)| r.findings.clone()).collect(),
        lines_scanned: combined_findings.iter().map(|(_, r)| r.lines_scanned).sum(),
    };

    if ui::confirm_continue(&synthetic) {
        eprintln!("aur-guard :: continuing install at the user's discretion.");
        Ok(ExitCode::from(0))
    } else {
        eprintln!("aur-guard :: install aborted by user (PreTransaction hook).");
        Ok(ExitCode::from(1))
    }
}

fn cmd_rules() -> Result<ExitCode> {
    let rules = patterns::build_rules();
    let color = ui::use_color();
    eprintln!("aur-guard :: {} active rules", rules.len());
    for r in rules {
        let sev = if color {
            format!("{}[{}]\x1b[0m", r.severity.color(), r.severity.label())
        } else {
            format!("[{}]", r.severity.label())
        };
        println!("{sev:18}  {}  {}", r.id, r.title);
    }
    Ok(ExitCode::from(0))
}

// --- utilities ---

fn exec_real(real: &Path, args: &[String]) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;
    let err = Command::new(real).args(args).exec();
    // If we get here, exec failed.
    anyhow::bail!("could not exec {}: {err}", real.display());
}

fn write_log(r: &ScanResult) {
    if std::fs::metadata("/var/log").is_ok() {
        if let Ok(meta) = std::fs::metadata(LOG_PATH) {
            if meta.permissions().readonly() {
                ui::append_log(FALLBACK_LOG, r);
                return;
            }
        }
        let parent = Path::new(LOG_PATH).parent().unwrap();
        if parent.exists()
            && std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(LOG_PATH)
                .is_ok()
        {
            ui::append_log(LOG_PATH, r);
            return;
        }
    }
    ui::append_log(FALLBACK_LOG, r);
}

fn list_foreign_packages() -> Vec<String> {
    let out = Command::new("pacman").arg("-Qmq").output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn pkg_name_only(target: &str) -> String {
    // pacman emits "pkgname" or sometimes "repo/pkgname"; take the last piece.
    target.rsplit('/').next().unwrap_or(target).to_string()
}

fn collect_cache_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    if let Ok(extra) = std::env::var("AUR_GUARD_CACHE_DIRS") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            out.push(PathBuf::from(p));
        }
    }

    // SUDO_USER gives us the real user when the hook runs as root.
    let users: Vec<String> = match std::env::var("SUDO_USER") {
        Ok(u) => vec![u],
        Err(_) => std::fs::read_dir("/home")
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default(),
    };

    for u in users {
        let home = PathBuf::from(format!("/home/{u}"));
        out.push(home.join(".cache/paru/clone"));
        out.push(home.join(".cache/yay"));
        out.push(home.join(".cache/aurutils/sync"));
    }

    out
}

fn find_pkgbuild(pkg: &str, caches: &[PathBuf]) -> Option<PathBuf> {
    for c in caches {
        let candidate = c.join(pkg).join("PKGBUILD");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
