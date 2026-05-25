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
    about = "Analizador de seguridad para PKGBUILDs del AUR.",
    long_about = "aur-guard analiza un PKGBUILD en busca de patrones maliciosos comunes \
                  (curl|bash, reverse shells, escritura en authorized_keys, sudo, suid, ...) \
                  y bloquea con confirmación interactiva."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analiza un PKGBUILD (o cualquier archivo) e imprime los hallazgos.
    Scan {
        /// Ruta al PKGBUILD. Si es un directorio, busca PKGBUILD dentro.
        path: PathBuf,
        /// Sin colores ni decoración.
        #[arg(long)]
        plain: bool,
    },
    /// Igual que `scan` pero el código de salida indica el resultado (0 limpio, 2 con hallazgos).
    Check {
        path: PathBuf,
        #[arg(long)]
        plain: bool,
        /// Severidad mínima a partir de la cual considerar fallo (low|medium|high|critical).
        #[arg(long, default_value = "high")]
        threshold: String,
    },
    /// Wrapper de makepkg: analiza el PKGBUILD del cwd y, si hay hallazgos, pide confirmación
    /// interactiva. Si se acepta, hace exec del makepkg real con los argumentos pasados.
    MakepkgWrap {
        /// Ruta al binario real de makepkg.
        #[arg(long, default_value = "/usr/bin/makepkg", env = "AUR_GUARD_REAL_MAKEPKG")]
        real: PathBuf,
        /// Argumentos pasados a makepkg.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Hook de pacman: lee paquetes objetivo por stdin (uno por línea), localiza el PKGBUILD
    /// en cachés conocidas de AUR helpers y emite advertencia / bloqueo si hay hallazgos.
    PacmanHook,
    /// Lista todas las reglas de detección activas.
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
        anyhow::ensure!(p.exists(), "no encontré PKGBUILD en {}", path.display());
        Ok(p)
    } else {
        anyhow::ensure!(path.exists(), "no existe la ruta {}", path.display());
        Ok(path.to_path_buf())
    }
}

fn cmd_scan(path: PathBuf, plain: bool) -> Result<ExitCode> {
    let path = resolve_pkgbuild(&path)?;
    let result = scanner::scan_file(&path).with_context(|| format!("leyendo {}", path.display()))?;
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
        "low" | "baja" => Severity::Low,
        "medium" | "med" | "media" => Severity::Medium,
        "high" | "alta" => Severity::High,
        "critical" | "crit" | "crítica" | "critica" => Severity::Critical,
        other => anyhow::bail!("umbral desconocido: {other}"),
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

    // Si no hay PKGBUILD aquí (p.ej. `makepkg --version`), pasa directo al real.
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
            eprintln!("aur-guard :: instalación abortada por el usuario.");
            return Ok(ExitCode::from(1));
        }
        eprintln!("aur-guard :: continuación confirmada por el usuario.");
    } else {
        eprintln!("aur-guard :: solo hallazgos menores; continuando sin pedir confirmación.");
    }

    exec_real(&real, &args)
}

fn cmd_pacman_hook() -> Result<ExitCode> {
    // pacman manda las rutas/objetos por stdin cuando NeedsTargets está activo.
    let mut targets = Vec::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let t = line.trim();
        if !t.is_empty() {
            targets.push(t.to_string());
        }
    }

    if targets.is_empty() {
        return Ok(ExitCode::from(0));
    }

    let foreign = list_foreign_packages();
    let caches = collect_cache_dirs();

    let mut combined_findings: Vec<(String, ScanResult)> = Vec::new();

    for pkg in targets {
        let name = pkg_name_only(&pkg);
        if !foreign.iter().any(|f| f == &name) {
            continue; // viene de los repositorios oficiales, no auditamos
        }
        if let Some(pkgbuild) = find_pkgbuild(&name, &caches) {
            match scanner::scan_file(&pkgbuild) {
                Ok(r) if !r.is_clean() => combined_findings.push((name, r)),
                Ok(r) => write_log(&r),
                Err(e) => eprintln!("aur-guard :: error escaneando {}: {e}", pkgbuild.display()),
            }
        } else {
            eprintln!(
                "aur-guard :: paquete AUR «{name}» — PKGBUILD no localizado en cachés conocidas; omito."
            );
        }
    }

    if combined_findings.is_empty() {
        return Ok(ExitCode::from(0));
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

    if critical_total + high_total == 0 {
        return Ok(ExitCode::from(0));
    }

    // Construimos un "result" sintético solo para el prompt.
    let synthetic = ScanResult {
        path: format!("{} paquete(s) AUR", combined_findings.len()),
        findings: combined_findings.iter().flat_map(|(_, r)| r.findings.clone()).collect(),
        lines_scanned: combined_findings.iter().map(|(_, r)| r.lines_scanned).sum(),
    };

    if ui::confirm_continue(&synthetic) {
        eprintln!("aur-guard :: instalación continuada bajo responsabilidad del usuario.");
        Ok(ExitCode::from(0))
    } else {
        eprintln!("aur-guard :: instalación abortada por el usuario (hook PreTransaction).");
        Ok(ExitCode::from(1))
    }
}

fn cmd_rules() -> Result<ExitCode> {
    let rules = patterns::build_rules();
    let color = ui::use_color();
    eprintln!("aur-guard :: {} reglas activas", rules.len());
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

// --- utilidades ---

fn exec_real(real: &Path, args: &[String]) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;
    let err = Command::new(real).args(args).exec();
    // si llegamos aquí, exec falló
    anyhow::bail!("no pude ejecutar {}: {err}", real.display());
}

fn write_log(r: &ScanResult) {
    if !ui::use_color() {
        // detección barata de "ejecución no interactiva" → escribimos en /var/log si podemos
    }
    if std::fs::metadata("/var/log").is_ok() {
        if let Ok(meta) = std::fs::metadata(LOG_PATH) {
            if meta.permissions().readonly() {
                ui::append_log(FALLBACK_LOG, r);
                return;
            }
        }
        // intentamos /var/log; si falla por permisos, vamos a /tmp
        let parent = Path::new(LOG_PATH).parent().unwrap();
        if parent.exists() {
            // probamos con un open append
            if std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(LOG_PATH)
                .is_ok()
            {
                ui::append_log(LOG_PATH, r);
                return;
            }
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
    // pacman emite "pkgname" o a veces "repo/pkgname"; tomamos la última pieza.
    target.rsplit('/').next().unwrap_or(target).to_string()
}

fn collect_cache_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    if let Ok(extra) = std::env::var("AUR_GUARD_CACHE_DIRS") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            out.push(PathBuf::from(p));
        }
    }

    // SUDO_USER nos da el usuario real cuando el hook corre como root.
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
