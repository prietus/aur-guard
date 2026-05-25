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
            regex: Regex::new($re).expect(concat!("invalid regex in rule ", $id)),
        }
    };
}

pub fn build_rules() -> Vec<Rule> {
    vec![
        // --- Remote content execution ---
        rule!(
            "AG001",
            Severity::Critical,
            "Remote download piped into a shell",
            "curl/wget/fetch output piped directly into bash/sh/zsh/etc. The downloaded content is unverified and can change between installs.",
            r"(?:curl|wget|fetch|aria2c)\s+[^\n|;&]*?\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh|fish|dash|ash)\b"
        ),
        rule!(
            "AG002",
            Severity::Critical,
            "Process substitution from remote download",
            "Equivalent to 'curl | bash' via bash <(curl ...). Executes remote content without verification.",
            r"(?:bash|sh|zsh|ksh|source|\.)\s+<\(\s*(?:curl|wget|fetch)\s"
        ),
        rule!(
            "AG003",
            Severity::Critical,
            "eval over remote download",
            "eval executes its argument as code. Combined with curl/wget it downloads and runs unverified code.",
            r#"eval\s+["`]?\$?\(\s*(?:curl|wget|fetch)\s"#
        ),
        rule!(
            "AG004",
            Severity::High,
            "source/. from a remote URL",
            "Loads and runs a script directly from the network instead of declaring it in the source array.",
            r#"(?:^|\s)(?:source|\.)\s+["']?https?://"#
        ),

        // --- Reverse shells ---
        rule!(
            "AG010",
            Severity::Critical,
            "netcat reverse shell (-e)",
            "netcat with -e executes a program on every connection; classic reverse shell pattern.",
            r"\bnc(?:at)?\s+(?:-[a-zA-Z]*e[a-zA-Z]*)\s+\S+\s+\d+"
        ),
        rule!(
            "AG011",
            Severity::Critical,
            "bash /dev/tcp reverse shell",
            "Classic reverse shell using bash's virtual /dev/tcp device.",
            r"bash\s+-i\s+>&?\s*/dev/(?:tcp|udp)/"
        ),
        rule!(
            "AG012",
            Severity::High,
            "Python reverse shell",
            "socket + pty + subprocess one-liner typical of reverse shells.",
            r#"python[0-9.]*\s+-c\s+["'][^"']*\b(?:socket|pty)\b[^"']*\b(?:dup2|spawn|connect)\b"#
        ),
        rule!(
            "AG013",
            Severity::High,
            "Perl reverse shell",
            "Perl with socket + exec is characteristic of reverse shells.",
            r#"perl\s+-e\s+["'][^"']*\bsocket\b[^"']*\bexec\b"#
        ),

        // --- Destructive commands ---
        rule!(
            "AG020",
            Severity::Critical,
            "Recursive rm aimed at the system root",
            "rm -rf at or near /. Even running as a normal user can wipe HOME, and --no-preserve-root can wipe the system itself.",
            r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:/(?:\s|\*|$)|~(?:\s|/|$)|\$HOME|\$ROOT)"
        ),
        rule!(
            "AG021",
            Severity::Critical,
            "dd writing to a block device",
            "dd with of=/dev/sd*, nvme*, vd*, hd* will destroy disk data.",
            r"\bdd\s+[^\n;&|]*\bof=/dev/(?:sd|nvme|hd|vd|mmcblk|loop|disk)"
        ),
        rule!(
            "AG022",
            Severity::Critical,
            "Filesystem format on a device",
            "mkfs/wipefs on a device destroys existing data.",
            r"\b(?:mkfs(?:\.\w+)?|wipefs|shred)\s+[^\n;&|]*/dev/"
        ),
        rule!(
            "AG023",
            Severity::Critical,
            "Fork bomb",
            "Classic bash fork bomb construct that exhausts system resources.",
            r":\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:"
        ),

        // --- Persistence / backdoor ---
        rule!(
            "AG030",
            Severity::High,
            "Writes to authorized_keys or system accounts",
            "Adding SSH keys or modifying passwd/shadow/sudoers from a PKGBUILD is a backdoor technique.",
            r#"(?:>>?|tee\s+(?:-a\s+)?)\s*["']?(?:(?:~|\$HOME|/root|/home/[^/\s]+)/\.ssh/authorized_keys|/etc/(?:passwd|shadow|sudoers(?:\.d)?))"#
        ),
        rule!(
            "AG031",
            Severity::High,
            "Modifies shell startup files",
            "Touching .bashrc, .zshrc, .profile, etc. from build() establishes persistence in the user's session.",
            r#"(?:>>?|tee\s+(?:-a\s+)?)\s*["']?(?:~|\$HOME|/root|/home/[^/\s]+)/\.(?:bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|profile|xprofile|xinitrc)"#
        ),
        rule!(
            "AG032",
            Severity::High,
            "crontab manipulation",
            "Adding entries to crontab or /etc/cron* is a common persistence mechanism.",
            r"(?:\bcrontab\s+-?[el]?\b|\|\s*crontab\b|>\s*/(?:etc|var/spool)/cron)"
        ),
        rule!(
            "AG033",
            Severity::High,
            "systemd unit enabled during build",
            "systemctl enable/start inside a PKGBUILD activates services without consent. This belongs in a .install scriptlet.",
            r"\bsystemctl\s+(?:--user\s+)?(?:enable|start|restart|--now)\b"
        ),
        rule!(
            "AG034",
            Severity::High,
            "User/group added during build",
            "useradd/groupadd/usermod outside an .install scriptlet may create privileged accounts behind the user's back.",
            r"\b(?:useradd|groupadd|usermod|gpasswd)\b"
        ),

        // --- Privilege escalation ---
        rule!(
            "AG040",
            Severity::High,
            "sudo inside the PKGBUILD",
            "makepkg refuses to run as root, so sudo inside a PKGBUILD is an attempt to gain privilege during build.",
            r"(?m)^[^#\n]*\bsudo\s+\S"
        ),
        rule!(
            "AG041",
            Severity::High,
            "Sets SUID/SGID bit",
            "chmod with numeric mode 4xxx/2xxx or +s allows execution with the file owner's privileges.",
            r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:[2467]\d{3}|[ugo]?\+s|u\+xs|g\+xs)\b"
        ),
        rule!(
            "AG042",
            Severity::High,
            "Capabilities granted to a binary",
            "setcap can grant elevated capabilities (cap_net_admin, cap_sys_admin, etc.) to packaged binaries.",
            r"\bsetcap\s+(?:cap_|all=)"
        ),

        // --- Obfuscation ---
        rule!(
            "AG050",
            Severity::High,
            "base64 payload decoded and executed",
            "base64 -d piped to bash/sh/eval typically hides payloads.",
            r"\b(?:base64\s+(?:-d|--decode)|openssl\s+(?:enc\s+)?-base64\s+-d)\b[^\n;&|]*\|\s*(?:bash|sh|zsh|eval)"
        ),
        rule!(
            "AG051",
            Severity::High,
            "Hex payload decoded and executed",
            "xxd -r or printf with \\x escapes piped to a shell hides payloads.",
            r#"\b(?:xxd\s+-r|printf\s+["'][^"']*(?:\\x[0-9a-fA-F]{2}){4,})[^\n;&|]*\|\s*(?:bash|sh|zsh)"#
        ),
        rule!(
            "AG052",
            Severity::Medium,
            "Variable holding a large base64 blob",
            "A variable assigned a long base64 string near an eval/decode call is a typical obfuscation pattern.",
            r#"=\s*["'][A-Za-z0-9+/]{120,}={0,2}["']"#
        ),

        // --- Network ---
        rule!(
            "AG060",
            Severity::Medium,
            "Connection to a literal IP",
            "Downloads or connections to raw IP addresses instead of domains. Unusual and harder to audit.",
            r"(?:curl|wget|nc|ncat|ssh|scp)\s+[^\n;&|]*\b(?:https?://|//)?(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        rule!(
            "AG061",
            Severity::Medium,
            "URL shortener as a source",
            "Shorteners hide the real destination and are extremely unusual in honest PKGBUILDs.",
            r"https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|cutt\.ly|rebrand\.ly)/"
        ),
        rule!(
            "AG062",
            Severity::Medium,
            "Tunneling (Cloudflare/ngrok/serveo)",
            "Reverse-tunnel services used to expose hosts. Not expected in a package build.",
            r"\b(?:ngrok|cloudflared|serveo\.net|localhost\.run|pinggy\.io|loophole\.cloud)\b"
        ),

        // --- Data exfiltration ---
        rule!(
            "AG070",
            Severity::High,
            "Reads user SSH keys",
            "Accessing private keys (~/.ssh/id_*) from a PKGBUILD has no legitimate justification.",
            r"(?:~|\$HOME|/root|/home/[^/\s]+)/\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|known_hosts)\b"
        ),
        rule!(
            "AG071",
            Severity::High,
            "Reads wallets / credentials / tokens",
            "Reads known credential files (wallets, gnome-keyring, browsers, .env).",
            r"(?:~|\$HOME|/root|/home/[^/\s]+)/(?:\.(?:bitcoin|electrum|ethereum|gnupg|aws|kube|docker|netrc|config/(?:google-chrome|chromium|BraveSoftware|Mozilla/firefox))|\.env)\b"
        ),
        rule!(
            "AG072",
            Severity::Medium,
            "Exfiltration via curl POST to external host",
            "curl with --data/-d or -F targeting an external host from a PKGBUILD can leak data.",
            r"curl\s+(?:-[a-zA-Z]+\s+)*(?:-X\s+POST|--data\b|-d\s|-F\s)\s*[^\n;&|]*https?://"
        ),
    ]
}
