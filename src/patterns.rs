use crate::report::Severity;
use regex::Regex;

pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
    pub regex: Regex,
}

macro_rules! rule {
    ($id:expr, $sev:expr, $title:expr, $desc:expr, $re:expr) => {
        Rule {
            id: $id,
            severity: $sev,
            title: $title,
            description: $desc,
            regex: Regex::new($re).expect(concat!("regex inválida en regla ", $id)),
        }
    };
}

pub fn build_rules() -> Vec<Rule> {
    vec![
        // --- Ejecución de contenido remoto ---
        rule!(
            "AG001",
            Severity::Critical,
            "Descarga remota canalizada a un shell",
            "curl/wget/fetch cuya salida se canaliza directamente a bash/sh/zsh/etc. El contenido descargado no se verifica y puede cambiar entre instalaciones.",
            r"(?:curl|wget|fetch|aria2c)\s+[^\n|;&]*?\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh|fish|dash|ash)\b"
        ),
        rule!(
            "AG002",
            Severity::Critical,
            "Sustitución de proceso con descarga remota",
            "Equivalente a 'curl | bash' pero usando bash <(curl ...). Ejecuta contenido remoto sin verificación.",
            r"(?:bash|sh|zsh|ksh|source|\.)\s+<\(\s*(?:curl|wget|fetch)\s"
        ),
        rule!(
            "AG003",
            Severity::Critical,
            "eval sobre descarga remota",
            "eval ejecuta su argumento como código. Combinado con curl/wget descarga y ejecuta código no verificado.",
            r#"eval\s+["`]?\$?\(\s*(?:curl|wget|fetch)\s"#
        ),
        rule!(
            "AG004",
            Severity::High,
            "source/. desde URL remota",
            "Cargar y ejecutar un script directamente desde la red sin descargarlo a la fuente del paquete.",
            r#"(?:^|\s)(?:source|\.)\s+["']?https?://"#
        ),

        // --- Reverse shells ---
        rule!(
            "AG010",
            Severity::Critical,
            "Reverse shell con netcat (-e)",
            "netcat con el flag -e ejecuta un programa en cada conexión; patrón clásico de reverse shell.",
            r"\bnc(?:at)?\s+(?:-[a-zA-Z]*e[a-zA-Z]*)\s+\S+\s+\d+"
        ),
        rule!(
            "AG011",
            Severity::Critical,
            "Reverse shell con bash /dev/tcp",
            "Patrón clásico de reverse shell usando el dispositivo virtual /dev/tcp de bash.",
            r"bash\s+-i\s+>&?\s*/dev/(?:tcp|udp)/"
        ),
        rule!(
            "AG012",
            Severity::High,
            "Reverse shell en Python",
            "Importación de socket+pty+subprocess típica de reverse shells en una sola línea.",
            r#"python[0-9.]*\s+-c\s+["'][^"']*\b(?:socket|pty)\b[^"']*\b(?:dup2|spawn|connect)\b"#
        ),
        rule!(
            "AG013",
            Severity::High,
            "Reverse shell en Perl",
            "Uso de Perl con socket+exec característico de reverse shells.",
            r#"perl\s+-e\s+["'][^"']*\bsocket\b[^"']*\bexec\b"#
        ),

        // --- Comandos destructivos ---
        rule!(
            "AG020",
            Severity::Critical,
            "rm recursivo apuntando a la raíz del sistema",
            "rm -rf en o cerca de /. Si se ejecuta como un usuario común aún puede destruir el HOME, y --no-preserve-root permite incluso destruir el sistema.",
            r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:/(?:\s|\*|$)|~(?:\s|/|$)|\$HOME|\$ROOT)"
        ),
        rule!(
            "AG021",
            Severity::Critical,
            "dd escribiendo a un dispositivo de bloque",
            "dd con of=/dev/sd*, nvme*, vd*, hd* destruirá los datos del disco.",
            r"\bdd\s+[^\n;&|]*\bof=/dev/(?:sd|nvme|hd|vd|mmcblk|loop|disk)"
        ),
        rule!(
            "AG022",
            Severity::Critical,
            "Formato de sistema de archivos",
            "mkfs/wipefs sobre un dispositivo. Destruye los datos existentes.",
            r"\b(?:mkfs(?:\.\w+)?|wipefs|shred)\s+[^\n;&|]*/dev/"
        ),
        rule!(
            "AG023",
            Severity::Critical,
            "Fork bomb",
            "Construcción típica de fork bomb en bash que agota recursos del sistema.",
            r":\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:"
        ),

        // --- Persistencia / backdoor ---
        rule!(
            "AG030",
            Severity::High,
            "Escritura en authorized_keys o cuentas del sistema",
            "Añadir claves SSH o modificar passwd/shadow/sudoers desde un PKGBUILD es una técnica de backdoor.",
            r#"(?:>>?|tee\s+(?:-a\s+)?)\s*["']?(?:(?:~|\$HOME|/root|/home/[^/\s]+)/\.ssh/authorized_keys|/etc/(?:passwd|shadow|sudoers(?:\.d)?))"#
        ),
        rule!(
            "AG031",
            Severity::High,
            "Modificación de archivos de inicio del shell",
            "Modificar .bashrc, .zshrc, .profile, etc., desde build() establece persistencia en la sesión del usuario.",
            r#"(?:>>?|tee\s+(?:-a\s+)?)\s*["']?(?:~|\$HOME|/root|/home/[^/\s]+)/\.(?:bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|profile|xprofile|xinitrc)"#
        ),
        rule!(
            "AG032",
            Severity::High,
            "Manipulación de crontab",
            "Añadir entradas al crontab o a /etc/cron* es un mecanismo común de persistencia.",
            r"(?:\bcrontab\s+-?[el]?\b|\|\s*crontab\b|>\s*/(?:etc|var/spool)/cron)"
        ),
        rule!(
            "AG033",
            Severity::High,
            "Activación de servicios systemd en build",
            "systemctl enable/start dentro de un PKGBUILD activa servicios sin consentimiento. Esto debe ir en un .install scriptlet.",
            r"\bsystemctl\s+(?:--user\s+)?(?:enable|start|restart|--now)\b"
        ),
        rule!(
            "AG034",
            Severity::High,
            "Adición de usuarios o grupos en build",
            "useradd/groupadd/usermod fuera de un scriptlet .install puede crear cuentas privilegiadas a espaldas del usuario.",
            r"\b(?:useradd|groupadd|usermod|gpasswd)\b"
        ),

        // --- Escalada de privilegios ---
        rule!(
            "AG040",
            Severity::High,
            "sudo dentro del PKGBUILD",
            "makepkg rehúsa ejecutarse como root, por lo que un sudo dentro del PKGBUILD intenta obtener privilegios durante la compilación.",
            r"(?m)^[^#\n]*\bsudo\s+\S"
        ),
        rule!(
            "AG041",
            Severity::High,
            "Establece bit SUID/SGID",
            "chmod con modo numérico 4xxx/2xxx o +s permite ejecución con privilegios del propietario del archivo.",
            r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:[2467]\d{3}|[ugo]?\+s|u\+xs|g\+xs)\b"
        ),
        rule!(
            "AG042",
            Severity::High,
            "Capabilities concedidas a un binario",
            "setcap puede otorgar capacidades elevadas (cap_net_admin, cap_sys_admin, etc.) a binarios del paquete.",
            r"\bsetcap\s+(?:cap_|all=)"
        ),

        // --- Ofuscación ---
        rule!(
            "AG050",
            Severity::High,
            "Payload base64 decodificado y ejecutado",
            "base64 -d canalizado a bash/sh/eval suele ocultar payloads.",
            r"\b(?:base64\s+(?:-d|--decode)|openssl\s+(?:enc\s+)?-base64\s+-d)\b[^\n;&|]*\|\s*(?:bash|sh|zsh|eval)"
        ),
        rule!(
            "AG051",
            Severity::High,
            "Payload hexadecimal decodificado y ejecutado",
            "xxd -r o printf con escapes \\x canalizados a un shell ocultan payloads.",
            r#"\b(?:xxd\s+-r|printf\s+["'][^"']*(?:\\x[0-9a-fA-F]{2}){4,})[^\n;&|]*\|\s*(?:bash|sh|zsh)"#
        ),
        rule!(
            "AG052",
            Severity::Medium,
            "Función bash con cuerpo en base64",
            "Variable con cadena base64 grande y eval/decodificación adyacente es patrón típico de ofuscación.",
            r#"=\s*["'][A-Za-z0-9+/]{120,}={0,2}["']"#
        ),

        // --- Red ---
        rule!(
            "AG060",
            Severity::Medium,
            "Conexión a IP literal",
            "Descargas o conexiones a direcciones IP en lugar de a un dominio. Inusual y dificulta auditoría.",
            r"(?:curl|wget|nc|ncat|ssh|scp)\s+[^\n;&|]*\b(?:https?://|//)?(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        rule!(
            "AG061",
            Severity::Medium,
            "Acortador de URL como fuente",
            "Los acortadores ocultan el destino real y son extraordinariamente inusuales en PKGBUILDs honestos.",
            r"https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|cutt\.ly|rebrand\.ly)/"
        ),
        rule!(
            "AG062",
            Severity::Medium,
            "Tunelización (Cloudflare/ngrok/serveo)",
            "Servicios de túnel inverso para exponer servicios. Inesperado en una build de paquete.",
            r"\b(?:ngrok|cloudflared|serveo\.net|localhost\.run|pinggy\.io|loophole\.cloud)\b"
        ),

        // --- Filtración de datos ---
        rule!(
            "AG070",
            Severity::High,
            "Lectura de claves SSH del usuario",
            "Acceder a claves privadas del usuario (~/.ssh/id_*) desde un PKGBUILD no tiene justificación.",
            r"(?:~|\$HOME|/root|/home/[^/\s]+)/\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|known_hosts)\b"
        ),
        rule!(
            "AG071",
            Severity::High,
            "Lectura de carteras / contraseñas / tokens",
            "Lectura de archivos de credenciales conocidos (wallets, gnome-keyring, navegadores, .env).",
            r"(?:~|\$HOME|/root|/home/[^/\s]+)/(?:\.(?:bitcoin|electrum|ethereum|gnupg|aws|kube|docker|netrc|config/(?:google-chrome|chromium|BraveSoftware|Mozilla/firefox))|\.env)\b"
        ),
        rule!(
            "AG072",
            Severity::Medium,
            "Filtración por curl POST a host externo",
            "curl con --data/-d o -F apuntando a un host externo desde un PKGBUILD puede filtrar datos.",
            r"curl\s+(?:-[a-zA-Z]+\s+)*(?:-X\s+POST|--data\b|-d\s|-F\s)\s*[^\n;&|]*https?://"
        ),
    ]
}
