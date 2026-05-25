#!/usr/bin/env bash
# Instalador de aur-guard.
#
#   sudo ./install.sh             instala todo (binario, shim de makepkg, hook de pacman, log)
#   sudo ./install.sh --no-hook   no instala el hook de pacman
#   sudo ./install.sh --no-shim   no instala el shim de makepkg en /usr/local/bin
#   sudo ./install.sh uninstall   elimina lo instalado por este script
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
            printf 'argumento desconocido: %s\n' "$arg" >&2
            exit 2
            ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    printf 'aur-guard :: se necesita root (use sudo).\n' >&2
    exit 1
fi

if [[ "$mode" == "uninstall" ]]; then
    rm -fv "$BIN_DIR/aur-guard"
    rm -fv "$BIN_DIR/makepkg"     # solo si era nuestro shim; el real vive en /usr/bin
    rm -fv "$HOOK_DIR/aur-guard.hook"
    printf 'aur-guard :: desinstalado. Log preservado en %s\n' "$LOG_FILE"
    exit 0
fi

# 1) compilar
if ! command -v cargo &>/dev/null; then
    printf 'aur-guard :: cargo no está en PATH.\n' >&2
    exit 1
fi
( cd "$SCRIPT_DIR" && cargo build --release --locked 2>/dev/null || cargo build --release )

install -d "$BIN_DIR"
install -m 0755 "$SCRIPT_DIR/target/release/aur-guard" "$BIN_DIR/aur-guard"
printf 'aur-guard :: binario instalado en %s/aur-guard\n' "$BIN_DIR"

# 2) shim de makepkg
if [[ "$want_shim" -eq 1 ]]; then
    if [[ -e "$BIN_DIR/makepkg" && ! -L "$BIN_DIR/makepkg" ]]; then
        # respaldamos cualquier archivo previo
        mv -v "$BIN_DIR/makepkg" "$BIN_DIR/makepkg.bak.$(date +%s)"
    fi
    install -m 0755 "$SCRIPT_DIR/scripts/makepkg" "$BIN_DIR/makepkg"
    printf 'aur-guard :: shim de makepkg instalado en %s/makepkg\n' "$BIN_DIR"
    printf '             (el makepkg real sigue en /usr/bin/makepkg)\n'
fi

# 3) hook de pacman
if [[ "$want_hook" -eq 1 ]]; then
    install -d "$HOOK_DIR"
    install -m 0644 "$SCRIPT_DIR/hooks/aur-guard.hook" "$HOOK_DIR/aur-guard.hook"
    printf 'aur-guard :: hook PreTransaction instalado en %s/aur-guard.hook\n' "$HOOK_DIR"
fi

# 4) log
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"
printf 'aur-guard :: log inicializado en %s\n' "$LOG_FILE"

printf '\naur-guard :: listo. Prueba:\n'
printf '  aur-guard rules\n'
printf '  aur-guard scan %s/test-fixtures/PKGBUILD.malicioso\n' "$SCRIPT_DIR"
