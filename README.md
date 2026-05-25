# aur-guard

Analizador de seguridad para PKGBUILDs del AUR. Detecta patrones maliciosos
comunes (`curl … | bash`, reverse shells, escritura en `authorized_keys`,
`sudo` dentro del PKGBUILD, bits suid, fork bombs, `dd` a `/dev/sd*`, checksums
todos en `SKIP`, fuentes sobre HTTP plano, etc.) **antes** de que `makepkg`
ejecute el script de build, y opcionalmente como segunda capa cuando pacman
está a punto de instalar.

> **Objetivo**: dar una red de seguridad ante PKGBUILDs comprometidos del AUR,
> sin necesidad de leer cada PKGBUILD a mano. No reemplaza la revisión manual,
> la complementa.

## Defensa en profundidad

`aur-guard` instala dos puntos de control:

1. **Shim de `makepkg`** (`/usr/local/bin/makepkg`) — se ejecuta *antes* del
   `makepkg` real. Es el único momento útil para **bloquear** la ejecución del
   PKGBUILD malicioso. Aplica también cuando paru, yay o cualquier AUR helper
   llama a `makepkg`.
2. **Hook PreTransaction de pacman** (`/etc/pacman.d/hooks/aur-guard.hook`) —
   segunda capa. Audita los PKGBUILDs de paquetes AUR (foreign) localizándolos
   en las cachés conocidas de los AUR helpers y permite abortar la transacción.

Ambos puntos preguntan **confirmación interactiva** por `/dev/tty` cuando hay
hallazgos de severidad alta o crítica. Si no hay terminal interactivo, bloquean
por defecto (salvo `AUR_GUARD_ASSUME=yes`).

## Instalación

```bash
git clone <repo> aur-guard
cd aur-guard
sudo ./install.sh
```

`install.sh` compila el binario en release, lo coloca en `/usr/local/bin/`,
instala el shim de `makepkg` y registra el hook de pacman. Opciones útiles:

```
sudo ./install.sh --no-hook    # solo el shim
sudo ./install.sh --no-shim    # solo el hook
sudo ./install.sh uninstall    # quita binario, shim y hook
```

## Uso

```bash
aur-guard scan PKGBUILD             # analiza e imprime los hallazgos
aur-guard scan /ruta/al/paquete/    # busca el PKGBUILD del directorio
aur-guard check PKGBUILD            # mismo escaneo, exit 0 limpio / 2 con hallazgos
aur-guard check --threshold critical PKGBUILD
aur-guard rules                     # lista todas las reglas activas
```

Una vez instalado el shim, el flujo es transparente:

```bash
yay -S algun-paquete-aur
# → paru/yay clona y llama a makepkg
# → el shim invoca aur-guard, que escanea el PKGBUILD
# → si hay hallazgos altos/críticos, pregunta y aborta si dices que no
# → si todo está limpio, exec al makepkg real
```

## Variables de entorno

| Variable | Efecto |
|---|---|
| `AUR_GUARD_DISABLE=1` | El shim de `makepkg` se salta el escaneo y llama directamente al makepkg real. |
| `AUR_GUARD_ASSUME=yes` | Cuando no hay TTY interactivo, se asume "sí" en la confirmación. **No usar en cron ni scripts no atendidos.** |
| `AUR_GUARD_REAL_MAKEPKG` | Ruta al `makepkg` real (por defecto `/usr/bin/makepkg`). |
| `AUR_GUARD_BIN` | Ruta al binario `aur-guard` que usa el shim (por defecto `/usr/local/bin/aur-guard`). |
| `AUR_GUARD_CACHE_DIRS` | Lista separada por `:` con cachés adicionales donde buscar PKGBUILDs (para el hook de pacman). |
| `NO_COLOR=1` | Desactiva colores en la salida. |

## Reglas

30 reglas agrupadas en familias. Ver `aur-guard rules` para la lista completa.

| Familia | Cubre |
|---|---|
| AG001–AG004 | Ejecución de contenido remoto (`curl|bash`, `bash <(curl)`, `eval $(curl)`, `source URL`) |
| AG010–AG013 | Reverse shells (nc -e, `/dev/tcp`, python, perl) |
| AG020–AG023 | Comandos destructivos (`rm -rf /`, `dd` a disco, `mkfs`, fork bomb) |
| AG030–AG034 | Persistencia (authorized_keys, .bashrc, crontab, systemd, useradd) |
| AG040–AG042 | Escalada (sudo en PKGBUILD, suid, setcap) |
| AG050–AG052 | Ofuscación (base64, xxd, cadenas base64 inmensas) |
| AG060–AG062 | Red sospechosa (IPs literales, acortadores, túneles) |
| AG070–AG072 | Acceso/filtración de credenciales y carteras |
| AG080–AG082 | Metadatos del PKGBUILD (checksums SKIP, fuentes http/git+http) |

Las severidades son `CRÍTICA`, `ALTA`, `MEDIA`, `BAJA`. Por defecto el shim
pide confirmación cuando hay al menos un hallazgo ≥ALTA.

## Limitaciones

- **No es un analizador estático completo de bash**. Las reglas son regex
  cuidadosas: pueden tener falsos positivos en proyectos extraños y falsos
  negativos si el atacante ofusca con suficiente esfuerzo. Es una red de
  seguridad, no una garantía.
- Un hook *puro* de pacman se ejecuta **después** de `makepkg`, así que solo
  el shim puede prevenir la ejecución del PKGBUILD malicioso. El hook sirve
  como auditoría y para abortar la instalación final.
- Si un atacante reemplaza el PKGBUILD por algo aparentemente benigno y la
  carga maliciosa vive en el tarball de fuentes (binario empaquetado, script
  llamado desde `make install`, etc.), `aur-guard` no lo verá. Las reglas
  AG080/AG081/AG082 al menos alertan cuando la integridad de las fuentes está
  desactivada o sobre canal sin cifrar.

## Añadir reglas

Editar `src/patterns.rs`, añadir una entrada con `rule!(id, severidad, título,
descripción, regex)`. Si el regex necesita matchear comillas, usar raw strings
con almohadilla: `r#"…"#`, no `r"…"`.

Probar con:

```bash
cargo build --release
./target/release/aur-guard scan test-fixtures/PKGBUILD.malicioso
```

## Licencia

MIT — ver [`LICENSE`](LICENSE).
