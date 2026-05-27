//! Parent-process detection + signalling.
//!
//! AUR helpers (yay, paru, pikaur, …) invoke `makepkg` several times during
//! a single `-S` run (clone → verifysource → build → fakeroot). When the
//! user declines our prompt and the shim exits non-zero, the helper treats
//! that as "build failed, retry" and calls makepkg again. The verdict
//! cache already short-circuits those retries silently, but the helper
//! still wastes its own retry budget and then asks the user about repo
//! deps anyway.
//!
//! The clean fix is to tell the AUR helper "the user said no, stop the
//! entire install loop" — which is exactly what SIGINT means in this
//! context (it's what Ctrl-C would deliver). We only do this when the
//! immediate parent process matches a known AUR helper, so we never
//! interrupt pacman, sudo, a shell script, or anything else by mistake.

use std::fs;

/// `comm` values for AUR helpers we recognise. Add more here as needed —
/// `comm` is the first 15 chars of the executable name, lower-case is
/// fine on all current helpers.
const AUR_HELPERS: &[&str] = &[
    "yay", "paru", "pikaur", "trizen", "aurutils", "aurman", "rua",
];

/// Read `/proc/<ppid>/comm` to find the immediate parent's executable
/// name. Returns `None` if /proc is unavailable, ppid is init (1), or the
/// read fails for any reason.
pub fn parent_comm() -> Option<String> {
    let ppid = unsafe { libc::getppid() };
    if ppid <= 1 {
        return None;
    }
    let raw = fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// `true` iff the immediate parent process is one of the AUR helpers we
/// know how to safely signal.
pub fn parent_is_aur_helper() -> bool {
    parent_comm()
        .map(|c| AUR_HELPERS.iter().any(|h| c.eq_ignore_ascii_case(h)))
        .unwrap_or(false)
}

/// Send SIGINT to the immediate parent process. The caller MUST gate this
/// on `parent_is_aur_helper()` first — sending SIGINT to pacman, sudo, or
/// a wrapping shell would cause more harm than good.
pub fn interrupt_parent() -> bool {
    let ppid = unsafe { libc::getppid() };
    if ppid <= 1 {
        return false;
    }
    unsafe { libc::kill(ppid, libc::SIGINT) == 0 }
}
