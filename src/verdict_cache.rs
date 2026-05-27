//! Short-lived verdict cache, keyed by a content hash of the PKGBUILD bundle.
//!
//! Without this cache the makepkg shim is invoked by yay/paru three or four
//! times per install (clone → verifysource → build → fakeroot package), and
//! the pacman PreTransaction hook fires once more on top of that. The user
//! ends up confirming the same SUSPICIOUS/MALICIOUS verdict four times in a
//! row for a single install.
//!
//! When the user (or the threshold rule) accepts a scan we drop a tiny file
//! into `$XDG_CACHE_HOME/aur-guard/verdicts/<hash>.txt` recording the verdict
//! and timestamp. Subsequent invocations within `TTL_SECS` that produce the
//! exact same bundle hash short-circuit the prompt with a one-liner.
//!
//! The hash includes:
//!   * the PKGBUILD content
//!   * every adjacent *.install scriptlet
//!   * the running aur-guard version (so upgrades invalidate the cache and
//!     fresh rules get a fresh prompt)
//!
//! Any mutation of any of these inputs produces a different hash, so the
//! cache cannot be used to slip a modified scriptlet past a prompt the user
//! already accepted for a benign-looking PKGBUILD.

use crate::report::Tier;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct CachedVerdict {
    pub tier: Tier,
    pub timestamp: u64,
}

impl CachedVerdict {
    pub fn age_secs(&self) -> u64 {
        current_unix().saturating_sub(self.timestamp)
    }
}

fn cache_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AUR_GUARD_VERDICT_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Ok(u) = std::env::var("SUDO_USER") {
        return Some(PathBuf::from(format!("/home/{u}/.cache/aur-guard/verdicts")));
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("aur-guard/verdicts"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache/aur-guard/verdicts"));
    }
    None
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute the bundle hash for a PKGBUILD path. Returns `None` only if the
/// PKGBUILD itself is unreadable; missing scriptlets are silently skipped so
/// the hash for "PKGBUILD only" is well-defined.
pub fn bundle_hash(pkgbuild: &Path) -> Option<String> {
    let pkgbuild_content = fs::read_to_string(pkgbuild).ok()?;
    let dir = pkgbuild.parent().unwrap_or(Path::new("."));

    let mut hasher = Sha256::new();
    hasher.update(b"aur-guard:v=");
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"\nPKGBUILD\n");
    hasher.update(pkgbuild_content.as_bytes());

    let mut install_files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|s| s.to_str()) == Some("install") && p.is_file()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    install_files.sort();

    for ifile in &install_files {
        if let Ok(content) = fs::read_to_string(ifile) {
            let name = ifile
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?.install");
            hasher.update(b"\n.install:");
            hasher.update(name.as_bytes());
            hasher.update(b"\n");
            hasher.update(content.as_bytes());
        }
    }

    let digest = hasher.finalize();
    Some(to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn entry_path(hash: &str) -> Option<PathBuf> {
    cache_dir().map(|d| d.join(format!("{hash}.txt")))
}

pub fn load(hash: &str) -> Option<CachedVerdict> {
    let path = entry_path(hash)?;
    let body = fs::read_to_string(path).ok()?;
    let mut lines = body.lines();
    let tier_str = lines.next()?;
    let ts: u64 = lines.next()?.parse().ok()?;
    if current_unix().saturating_sub(ts) > TTL_SECS {
        return None;
    }
    let tier = Tier::parse(tier_str)?;
    Some(CachedVerdict { tier, timestamp: ts })
}

pub fn save(hash: &str, tier: Tier) -> io::Result<()> {
    let Some(path) = entry_path(hash) else { return Ok(()) };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = format!("{}\n{}\n", tier.label().to_lowercase(), current_unix());
    fs::write(path, body)?;
    if let Some(dir) = cache_dir() {
        prune_expired(&dir);
    }
    Ok(())
}

fn prune_expired(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let cutoff = TTL_SECS.saturating_mul(4);
    for entry in rd.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else { continue };
        let Ok(age) = SystemTime::now().duration_since(modified) else { continue };
        if age.as_secs() > cutoff {
            let _ = fs::remove_file(entry.path());
        }
    }
}
