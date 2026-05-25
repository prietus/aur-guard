#!/usr/bin/env bash
# Installer for aur-guard.
#
#   sudo ./install.sh             install everything (binary, makepkg shim, pacman hook, log)
#   sudo ./install.sh --no-hook   do not install the pacman hook
#   sudo ./install.sh --no-shim   do not install the makepkg shim in /usr/local/bin
#   sudo ./install.sh uninstall   remove everything this script installs
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
HOOK_DIR="/etc/pacman.d/hooks"
LOG_FILE="/var/log/aur-guard.log"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

want_hook=1
want_shim=1
mode="install"
for arg in "$@"; do
    case "$arg" in
        --no-hook) want_hook=0 ;;
        --no-shim) want_shim=0 ;;
        install)   mode="install" ;;
        uninstall) mode="uninstall" ;;
        -h|--help)
            sed -n '2,8p' "$0"
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$arg" >&2
            exit 2
            ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    printf 'aur-guard :: root required (use sudo).\n' >&2
    exit 1
fi

if [[ "$mode" == "uninstall" ]]; then
    rm -fv "$BIN_DIR/aur-guard"
    rm -fv "$BIN_DIR/makepkg"     # only our shim; the real one lives in /usr/bin
    rm -fv "$HOOK_DIR/aur-guard.hook"
    printf 'aur-guard :: uninstalled. Log preserved at %s\n' "$LOG_FILE"
    exit 0
fi

# 1) build
if ! command -v cargo &>/dev/null; then
    printf 'aur-guard :: cargo is not in PATH.\n' >&2
    exit 1
fi
( cd "$SCRIPT_DIR" && cargo build --release --locked 2>/dev/null || cargo build --release )

install -d "$BIN_DIR"
install -m 0755 "$SCRIPT_DIR/target/release/aur-guard" "$BIN_DIR/aur-guard"
printf 'aur-guard :: binary installed at %s/aur-guard\n' "$BIN_DIR"

# 2) makepkg shim
if [[ "$want_shim" -eq 1 ]]; then
    if [[ -e "$BIN_DIR/makepkg" && ! -L "$BIN_DIR/makepkg" ]]; then
        # back up any pre-existing file
        mv -v "$BIN_DIR/makepkg" "$BIN_DIR/makepkg.bak.$(date +%s)"
    fi
    install -m 0755 "$SCRIPT_DIR/scripts/makepkg" "$BIN_DIR/makepkg"
    printf 'aur-guard :: makepkg shim installed at %s/makepkg\n' "$BIN_DIR"
    printf '             (the real makepkg still lives at /usr/bin/makepkg)\n'
fi

# 3) pacman hook
if [[ "$want_hook" -eq 1 ]]; then
    install -d "$HOOK_DIR"
    install -m 0644 "$SCRIPT_DIR/hooks/aur-guard.hook" "$HOOK_DIR/aur-guard.hook"
    printf 'aur-guard :: PreTransaction hook installed at %s/aur-guard.hook\n' "$HOOK_DIR"
fi

# 4) log
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"
printf 'aur-guard :: log initialised at %s\n' "$LOG_FILE"

printf '\naur-guard :: done. Try:\n'
printf '  aur-guard rules\n'
printf '  aur-guard scan %s/test-fixtures/PKGBUILD.malicious\n' "$SCRIPT_DIR"
