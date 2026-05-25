# aur-guard

Security scanner for AUR PKGBUILDs. Detects common malicious patterns
(`curl … | bash`, reverse shells, writes to `authorized_keys`, `sudo` inside
the PKGBUILD, suid bits, fork bombs, `dd` to `/dev/sd*`, all-`SKIP` checksums,
sources over plain HTTP, etc.) **before** `makepkg` runs the build script, and
optionally as a second layer right before pacman installs the package.

> **Goal**: provide a safety net against compromised AUR PKGBUILDs without
> having to read every PKGBUILD by hand. It does not replace manual review —
> it complements it.

## Defence in depth

`aur-guard` installs two checkpoints:

1. **`makepkg` shim** (`/usr/local/bin/makepkg`) — runs *before* the real
   `makepkg`. This is the only useful point at which a malicious PKGBUILD can
   actually be **blocked**. It also fires when paru, yay or any AUR helper
   invokes `makepkg`.
2. **pacman PreTransaction hook** (`/etc/pacman.d/hooks/aur-guard.hook`) —
   second layer. Audits the PKGBUILDs of foreign (AUR) packages by locating
   them in the known AUR-helper caches, and lets you abort the transaction.

Both checkpoints prompt for **interactive confirmation** over `/dev/tty` when
there are high- or critical-severity findings. With no interactive terminal,
they block by default (unless `AUR_GUARD_ASSUME=yes`).

## Install

```bash
git clone <repo> aur-guard
cd aur-guard
sudo ./install.sh
```

`install.sh` builds the release binary, places it in `/usr/local/bin/`,
installs the `makepkg` shim and registers the pacman hook. Useful flags:

```
sudo ./install.sh --no-hook    # shim only
sudo ./install.sh --no-shim    # hook only
sudo ./install.sh uninstall    # remove binary, shim and hook
```

## Usage

```bash
aur-guard scan PKGBUILD             # scan and print findings
aur-guard scan /path/to/package/    # finds PKGBUILD inside the directory
aur-guard check PKGBUILD            # same scan; exit 0 if clean, 2 with findings
aur-guard check --threshold critical PKGBUILD
aur-guard rules                     # list every active rule
```

Once the shim is installed the flow is transparent:

```bash
yay -S some-aur-package
# → paru/yay clones and calls makepkg
# → the shim invokes aur-guard, which scans the PKGBUILD
# → on high/critical findings it asks for confirmation and aborts on "no"
# → if clean, it execs the real makepkg
```

## Environment variables

| Variable | Effect |
|---|---|
| `AUR_GUARD_DISABLE=1` | The `makepkg` shim skips the scan and calls the real makepkg directly. |
| `AUR_GUARD_ASSUME=yes` | With no interactive TTY, assume "yes" at the prompt. **Do not use in cron or unattended scripts.** |
| `AUR_GUARD_REAL_MAKEPKG` | Path to the real `makepkg` (default `/usr/bin/makepkg`). |
| `AUR_GUARD_BIN` | Path to the `aur-guard` binary used by the shim (default `/usr/local/bin/aur-guard`). |
| `AUR_GUARD_CACHE_DIRS` | Colon-separated list of extra directories where the pacman hook should look for PKGBUILDs. |
| `NO_COLOR=1` | Disable coloured output. |

## Rules

30 rules grouped into families. Run `aur-guard rules` for the full list.

| Family | Covers |
|---|---|
| AG001–AG004 | Remote content execution (`curl|bash`, `bash <(curl)`, `eval $(curl)`, `source URL`) |
| AG010–AG013 | Reverse shells (nc -e, `/dev/tcp`, python, perl) |
| AG020–AG023 | Destructive commands (`rm -rf /`, `dd` to disk, `mkfs`, fork bomb) |
| AG030–AG034 | Persistence (authorized_keys, .bashrc, crontab, systemd, useradd) |
| AG040–AG042 | Privilege escalation (sudo in PKGBUILD, suid, setcap) |
| AG050–AG052 | Obfuscation (base64, xxd, huge base64 strings) |
| AG060–AG062 | Suspicious network (literal IPs, URL shorteners, tunnels) |
| AG070–AG072 | Credential / wallet access and exfiltration |
| AG080–AG082 | PKGBUILD metadata (SKIP checksums, http / git+http sources) |

Severities are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. By default the shim asks
for confirmation when at least one finding is ≥HIGH.

## Limitations

- **Not a full bash static analyser**. The rules are carefully tuned regexes:
  they may produce false positives in unusual projects and false negatives if
  an attacker obfuscates with enough effort. This is a safety net, not a
  guarantee.
- A *pure* pacman hook runs **after** `makepkg`, so only the shim can prevent
  the malicious PKGBUILD from executing. The hook serves as auditing and as a
  way to abort the final install.
- If an attacker replaces the PKGBUILD with something that looks benign and
  ships the malicious payload inside the source tarball (a packaged binary, a
  script called from `make install`, etc.), `aur-guard` will not see it. Rules
  AG080/AG081/AG082 at least warn when source integrity is disabled or sent
  over an unencrypted channel.

## Adding rules

Edit `src/patterns.rs` and add a `rule!(id, severity, title, description,
regex)` entry. If the regex needs to match quote characters, use hash raw
strings (`r#"…"#`) rather than `r"…"`.

Test with:

```bash
cargo build --release
./target/release/aur-guard scan test-fixtures/PKGBUILD.malicious
```

## License

MIT — see [`LICENSE`](LICENSE).
