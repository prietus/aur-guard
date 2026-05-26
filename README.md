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
the scan lands at tier `SUSPICIOUS` or worse (see *Scoring model* below). With
no interactive terminal, they block by default (unless `AUR_GUARD_ASSUME=yes`).

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
aur-guard check PKGBUILD            # exit 0 below threshold, 2 at or above
aur-guard check --threshold malicious PKGBUILD   # only block on tier MALICIOUS
aur-guard rules                     # list every active rule
```

`check` defaults to `--threshold suspicious`. Valid thresholds:
`trusted | ok | sketchy | suspicious | malicious`.

Once the shim is installed the flow is transparent:

```bash
yay -S some-aur-package
# → paru/yay clones and calls makepkg
# → the shim invokes aur-guard, which scans the PKGBUILD
# → tier SUSPICIOUS or worse → confirmation prompt, abort on "no"
# → otherwise it execs the real makepkg
```

## Scoring model

Every scan ends with one of five tiers and a **trust score 0–100** (higher is
safer):

| Tier | Trust | Decision (shim / hook) |
|---|---|---|
| `TRUSTED` | 90–100 | runs silently |
| `OK` | 70–89 | runs silently |
| `SKETCHY` | 50–69 | prints findings, **no prompt** |
| `SUSPICIOUS` | 25–49 | prints findings, **prompts** |
| `MALICIOUS` | 0–24 | prints findings, **prompts** |

Each rule contributes a number of *risk points*. Total risk is the sum of
points (capped at 100); trust is `100 − risk`. A handful of rules are
**override gates**: a single match forces the result to `MALICIOUS` regardless
of the cumulative score. The gates are unambiguous indicators of malice —
`curl … | bash`, classic reverse shells, `rm -rf /`, fork bomb, `base64 -d |
bash`, etc. — and they are marked with `⛔gate` in `aur-guard rules`.

Per-finding badges (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`) are a display
shorthand derived from the rule's points; they describe *how heavy a single
match is*, not the overall verdict. The tier on the first output line is what
the shim and hook actually decide on.

## Integration with AUR helpers

aur-guard plugs into AUR helpers (paru, yay, pikaur, trizen, aurutils, …)
**through PATH order**, without touching the helper's configuration. There is
nothing to register, no plugin to install — only one assumption: that
`/usr/local/bin` sits before `/usr/bin` in your PATH.

### Why the PATH trick works

On a default Arch user account the PATH looks like:

```
/usr/local/sbin:/usr/local/bin:/usr/bin
```

Every AUR helper invokes `makepkg` by name, letting the shell resolve it
through PATH. With `/usr/local/bin` first, the binary the helper finds is the
aur-guard shim. The shim scans the `PKGBUILD` in the current working directory
and, if the user accepts (or there are no findings), `exec`s the real
`/usr/bin/makepkg` with the original arguments. The helper sees the exit code
of the real makepkg and behaves exactly as it would have without the shim.

### Verify it is wired up

```bash
which makepkg
# expected: /usr/local/bin/makepkg
```

If you instead see `/usr/bin/makepkg`, something (a shell rc file, an entry in
`/etc/profile.d/`, a custom systemd user unit) is putting `/usr/bin` before
`/usr/local/bin`. Fix the PATH or use one of the explicit integrations below.

### Helper-by-helper status

| Helper | Default behaviour | Notes |
|---|---|---|
| **paru** | Works out of the box | The config key `[bin] Makepkg = "makepkg"` is the default and resolves via PATH. If you previously set it to an absolute path (`/usr/bin/makepkg`) in `~/.config/paru/paru.conf` or `/etc/paru.conf`, change it back to `"makepkg"` or point it at `"/usr/local/bin/makepkg"`. |
| **yay** | Works out of the box | Same situation: `MakepkgBin` defaults to `makepkg`. Check it with `yay -P --getconfig \| grep -i makepkg`. If you ran `yay --save --makepkg /usr/bin/makepkg` at some point, undo it with `yay --save --makepkg makepkg`. |
| **pikaur** | Works out of the box | Resolves `makepkg` through PATH. |
| **trizen** | Works out of the box | Same. |
| **aurutils** (`aur build`) | Works out of the box | Same. |
| **paru `--chroot`** or **yay `--chroot`** | **Does not see the shim** | These build inside a clean systemd-nspawn / `mkarchroot` container that has no `/usr/local/bin/makepkg`. The pacman PreTransaction hook still fires once the resulting `.pkg.tar.zst` is about to be installed, so the second layer of defence still applies. |
| Manual `pacman -U some-package.pkg.tar.zst` | Hook only | The shim is bypassed entirely because makepkg is not invoked, but the pacman hook still audits the PKGBUILD if it is available in a known AUR-helper cache. |

### Explicit integrations (if you do not want to rely on PATH)

Both points below are optional. Use them if the PATH trick is not viable in
your environment.

**paru `PreBuildCommand`** — paru natively supports running a command before
each build. In `~/.config/paru/paru.conf` (or `/etc/paru.conf`):

```ini
[bin]
PreBuildCommand = /usr/local/bin/aur-guard check --threshold malicious .
```

`PreBuildCommand` is treated as a gate by paru: if it exits non-zero, paru
aborts the build. Because there is no interactive prompt in this slot, pick a
threshold deliberately: `malicious` only blocks on tier `MALICIOUS` (override
gate fired or score ≤ 24); use `suspicious` if you want to fail on borderline
PKGBUILDs too.

**yay** does not expose a pre-build hook. With yay, stick to the PATH shim, or
use the two-step flow:

```bash
yay -G some-aur-package           # only clone the package
aur-guard scan some-aur-package/  # scan
cd some-aur-package && makepkg -si
```

### Skipping the scan for a single command

Sometimes you really do want to bypass the scan (you have already audited the
PKGBUILD by hand, you are reinstalling a known-good package, …):

```bash
AUR_GUARD_DISABLE=1 yay -S some-aur-package
```

The shim detects the variable and `exec`s the real makepkg directly without
scanning. The pacman hook is independent and will still run unless you also
remove or disable `/etc/pacman.d/hooks/aur-guard.hook`.

### Why both layers (shim + pacman hook)?

The shim is the only checkpoint that runs **before** the PKGBUILD executes,
so it is the only one that can prevent a `prepare()`/`build()` payload from
doing damage. The pacman hook is downstream and only sees the already-built
`.pkg.tar.zst`, but it covers cases the shim cannot: chroot builds, manual
`pacman -U`, sudo PATH issues, and corrupted helper configs. The two layers
together mean a malicious PKGBUILD has to slip past both PATH resolution and
the post-build audit.

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

32 detection rules — 29 regex-based (visible in `aur-guard rules`) plus 3
PKGBUILD-metadata checks built into the scanner. Grouped by family:

| Family | Covers | Gates |
|---|---|---|
| AG001–AG004 | Remote content execution (`curl|bash`, `bash <(curl)`, `eval $(curl)`, `source URL`) | AG001-003 |
| AG010–AG013 | Reverse shells (nc -e, `/dev/tcp`, python, perl) | AG010-011 |
| AG020–AG023 | Destructive commands (`rm -rf /`, `dd` to disk, `mkfs`, fork bomb) | all |
| AG030–AG034 | Persistence (authorized_keys, .bashrc, crontab, systemd, useradd) | — |
| AG040–AG042 | Privilege escalation (sudo in PKGBUILD, suid, setcap) | — |
| AG050–AG052 | Obfuscation (base64, xxd, huge base64 strings) | AG050-051 |
| AG060–AG062 | Suspicious network (literal IPs, URL shorteners, tunnels) | — |
| AG070–AG072 | Credential / wallet access and exfiltration | — |
| AG080–AG082 | PKGBUILD metadata (SKIP checksums, http / git+http sources) | — |

Rules marked as gates force the result to tier `MALICIOUS` on a single match.
The rest accumulate points into the trust score (see *Scoring model*).

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

Edit `src/patterns.rs` and add a `rule!(id, points, override_gate, title,
description, regex)` entry:

- `points`: how much risk the rule contributes (0–100). Roughly: 30 = mild
  smell, 50 = significant, 75 = strong signal, 95 = essentially proof.
- `override_gate`: set to `true` only for unambiguous indicators of malice —
  one match alone should be enough to declare the package `MALICIOUS`.

If the regex needs to match quote characters, use hash raw strings (`r#"…"#`)
rather than `r"…"`.

Test with:

```bash
cargo build --release
./target/release/aur-guard scan test-fixtures/PKGBUILD.malicious
./target/release/aur-guard scan test-fixtures/PKGBUILD.benign
```

Expected: malicious lands at `MALICIOUS` (trust 0/100, override gate fired),
benign at `TRUSTED` (trust 100/100, no findings).

## License

MIT — see [`LICENSE`](LICENSE).
