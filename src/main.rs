mod diff;
mod patterns;
mod report;
mod rpc;
mod scanner;
mod ui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::report::{ScanResult, Tier};

const LOG_PATH: &str = "/var/log/aur-guard.log";
const FALLBACK_LOG: &str = "/tmp/aur-guard.log";

#[derive(Parser)]
#[command(
    name = "aur-guard",
    version,
    about = "Security scanner for AUR PKGBUILDs.",
    long_about = "aur-guard scans a PKGBUILD (and adjacent .install scriptlets) \
                  for common malicious patterns, optionally diffs against the \
                  previously-seen version of the same package to flag freshly \
                  introduced payloads, and can block the install interactively."
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
        /// Skip the supply-chain diff against the cached previous version.
        #[arg(long)]
        no_diff: bool,
        /// Skip the AUR RPC reputation lookup (no network).
        #[arg(long)]
        no_network: bool,
    },
    /// Same as `scan` but the exit code reflects the result (0 below threshold, 2 at or above).
    Check {
        path: PathBuf,
        #[arg(long)]
        plain: bool,
        /// Minimum tier that triggers a non-zero exit
        /// (trusted|ok|sketchy|suspicious|malicious).
        #[arg(long, default_value = "suspicious")]
        threshold: String,
        /// Skip the supply-chain diff against the cached previous version.
        #[arg(long)]
        no_diff: bool,
        /// Skip the AUR RPC reputation lookup (no network).
        #[arg(long)]
        no_network: bool,
    },
    /// makepkg wrapper: scan the PKGBUILD in the cwd and, if the result is
    /// concerning, ask for interactive confirmation. On accept, exec the real
    /// makepkg with the given arguments.
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
        Cmd::Scan { path, plain, no_diff, no_network } => cmd_scan(path, plain, no_diff, no_network),
        Cmd::Check { path, plain, threshold, no_diff, no_network } => {
            cmd_check(path, plain, &threshold, no_diff, no_network)
        }
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

/// One-stop scan used by every CLI path. Scans the PKGBUILD + adjacent
/// `*.install` scriptlets, optionally diffs against the cached previous
/// version, and optionally enriches with AUR RPC reputation data.
fn full_scan(path: &Path, with_diff: bool, with_network: bool) -> Result<ScanResult> {
    let mut result = scanner::scan_pkgbuild_bundle(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let current = std::fs::read_to_string(path).unwrap_or_default();
    let pkgname = diff::pkgname_from(&current);

    if with_diff {
        if let Some(name) = &pkgname {
            if let Some(prev) = diff::load_previous(name) {
                diff::mark_new_findings(&mut result.findings, &prev, &current);
                diff::escalate_tier(&mut result);
            }
            let _ = diff::save_current(name, &current);
        }
    }

    if with_network && !rpc::network_disabled() {
        if let Some(name) = &pkgname {
            if let Some(info) = rpc::fetch(name) {
                rpc::apply(&mut result, name, &info);
            }
        }
    }

    Ok(result)
}

fn cmd_scan(path: PathBuf, plain: bool, no_diff: bool, no_network: bool) -> Result<ExitCode> {
    let path = resolve_pkgbuild(&path)?;
    let result = full_scan(&path, !no_diff, !no_network)?;
    let color = !plain && ui::use_color();
    ui::print_result(&result, color);
    Ok(if result.is_clean() {
        ExitCode::from(0)
    } else {
        ExitCode::from(2)
    })
}

fn parse_threshold(s: &str) -> Result<Tier> {
    Tier::parse(s).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown threshold {s:?}; expected one of: trusted, ok, sketchy, suspicious, malicious"
        )
    })
}

fn cmd_check(
    path: PathBuf,
    plain: bool,
    threshold: &str,
    no_diff: bool,
    no_network: bool,
) -> Result<ExitCode> {
    let thr = parse_threshold(threshold)?;
    let path = resolve_pkgbuild(&path)?;
    let result = full_scan(&path, !no_diff, !no_network)?;
    let color = !plain && ui::use_color();
    ui::print_result(&result, color);
    Ok(if result.tier >= thr {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    })
}

fn cmd_makepkg_wrap(real: PathBuf, args: Vec<String>) -> Result<ExitCode> {
    let cwd = std::env::current_dir()?;
    let pkgbuild = cwd.join("PKGBUILD");

    // If there is no PKGBUILD here (e.g. `makepkg --version`), forward as-is.
    if !pkgbuild.exists() {
        return exec_real(&real, &args);
    }

    let result = full_scan(&pkgbuild, true, true)?;
    let color = ui::use_color();
    ui::print_result(&result, color);
    write_log(&result);

    // Trusted/Ok run through. Sketchy prints findings but doesn't prompt.
    // Suspicious/Malicious require interactive confirmation.
    if result.tier < Tier::Suspicious {
        if result.tier == Tier::Sketchy {
            eprintln!("aur-guard :: tier SKETCHY; continuing without prompt.");
        }
        return exec_real(&real, &args);
    }

    if !ui::confirm_continue(&result) {
        eprintln!("aur-guard :: install aborted by user.");
        return Ok(ExitCode::from(1));
    }
    eprintln!("aur-guard :: user confirmed; continuing.");
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

    let mut scanned: Vec<(String, ScanResult)> = Vec::new();
    let mut missing_count = 0usize;

    for name in &aur_targets {
        if let Some(pkgbuild) = find_pkgbuild(name, &caches) {
            match full_scan(&pkgbuild, true, true) {
                Ok(r) => scanned.push((name.clone(), r)),
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
    let mut tier_counts = [0usize; 5]; // Trusted, Ok, Sketchy, Suspicious, Malicious
    let mut worst_tier = Tier::Trusted;
    for (_, r) in &scanned {
        ui::print_result(r, color);
        write_log(r);
        tier_counts[tier_index(r.tier)] += 1;
        if r.tier > worst_tier {
            worst_tier = r.tier;
        }
    }

    eprintln!(
        "aur-guard :: {} AUR target(s) — trusted={} ok={} sketchy={} suspicious={} malicious={} (skipped {}).",
        aur_targets.len(),
        tier_counts[0],
        tier_counts[1],
        tier_counts[2],
        tier_counts[3],
        tier_counts[4],
        missing_count,
    );

    if worst_tier < Tier::Suspicious {
        return Ok(ExitCode::from(0));
    }

    let synthetic = scanner::aggregate(
        &scanned,
        format!("{} AUR package(s)", scanned.len()),
    );

    if ui::confirm_continue(&synthetic) {
        eprintln!("aur-guard :: continuing install at the user's discretion.");
        Ok(ExitCode::from(0))
    } else {
        eprintln!("aur-guard :: install aborted by user (PreTransaction hook).");
        Ok(ExitCode::from(1))
    }
}

fn tier_index(t: Tier) -> usize {
    match t {
        Tier::Trusted => 0,
        Tier::Ok => 1,
        Tier::Sketchy => 2,
        Tier::Suspicious => 3,
        Tier::Malicious => 4,
    }
}

fn cmd_rules() -> Result<ExitCode> {
    let regex_rules = patterns::build_rules();
    let meta_rules = scanner::metadata_rules();
    let rep_rules = rpc::reputation_rules();
    let color = ui::use_color();
    let total = regex_rules.len() + meta_rules.len() + rep_rules.len();
    eprintln!(
        "aur-guard :: {} active rules ({} regex + {} metadata + {} reputation)",
        total,
        regex_rules.len(),
        meta_rules.len(),
        rep_rules.len(),
    );
    for r in regex_rules {
        print_rule(color, r.id, r.points, r.override_gate, r.title);
    }
    for r in meta_rules {
        print_rule(color, r.id, r.points, r.override_gate, r.title);
    }
    for r in rep_rules {
        print_rule(color, r.id, r.points, r.override_gate, r.title);
    }
    Ok(ExitCode::from(0))
}

fn print_rule(color: bool, id: &str, points: u32, override_gate: bool, title: &str) {
    let sev = report::Severity::from_points(points, override_gate);
    let badge = if color {
        format!("{}[{}]\x1b[0m", sev.color(), sev.label())
    } else {
        format!("[{}]", sev.label())
    };
    let gate = if override_gate { " ⛔gate" } else { "      " };
    println!("{badge:18}  {}  {:>2}pts {}  {}", id, points, gate, title);
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
