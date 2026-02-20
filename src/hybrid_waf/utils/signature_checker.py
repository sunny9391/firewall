import re
from typing import Literal

# ── SQL Injection ─────────────────────────────────────────────────────────────
_SQL = [
    r"(?i)(\bunion\b\s+(\ball\b\s+)?)\bselect\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\binsert\s+into\b",
    r"(?i)\bdelete\s+from\b",
    r"(?i)\bupdate\b.+\bset\b",
    r"(?i)\bor\s+1\s*=\s*1",
    r"(?i)\band\s+1\s*=\s*[01]",
    r"(?i)'\s*or\s*'1'\s*=\s*'1",
    r"(?i)1'\s*or\s*1\s*=\s*1",
    r"(?i)admin'\s*--",
    r"(?i)'\s*and\s+sleep\s*\(",
    r"(?i)\bwaitfor\s+delay\b",
    r"(?i)\bexec\s+xp_cmdshell\b",
    r"(?i)\bselect\s+\*",
    r"(?i);\s*shutdown\s*--",
    r"(?i)'\s*having\s+1\s*=\s*1",
    r"(?i)'\s*and\s+ascii\s*\(",
    r"(?i)'\s*and\s+extractvalue\s*\(",
    r"(?i)\border\s+by\s+\d+",
    r"(?i)convert\s*\(\s*int\s*,",
    r"(?i)select\s+(username|password|@@version|@@datadir|load_file|user\(\)|database\(\))",
    r"(?i)union\s+select",
    r"/\*.*?\*/",
    r"--(?:\s|$)",
]

# ── XSS ──────────────────────────────────────────────────────────────────────
_XSS = [
    r"(?i)<script[\s>]",
    r"(?i)</script>",
    r"(?i)<img\s[^>]*src\s*=",
    r"(?i)\bon\w+\s*=",
    r"(?i)\bjavascript\s*:",
    r"(?i)<iframe[\s>]",
    r"(?i)<svg[\s>]",
    r"(?i)\beval\s*\(",
    r"(?i)\bdocument\.cookie\b",
    r"(?i)\bwindow\.location\s*=",
    r"(?i)\bself\.location\s*=",
    r"(?i)String\.fromCharCode\s*\(",
    r"&#x[0-9a-f]+;",
    r"(?i)&lt;script",
    r"(?i)<embed[\s>]",
    r"(?i)<object[\s>]",
    r"(?i)src\s*=\s*javascript:",
    r"(?i)data:text/html",
    r"(?i)constructor\.constructor\s*\(",
    r"(?i)\b(prompt|confirm|alert)\s*\(",
    r"(?i)\bconsole\.(log|warn|error)\s*\(",
    r"(?i)set(timeout|interval)\s*\(",
    r"(?i)innerHTML\s*=",
    r"(?i)srcdoc\s*=",
]

# ── HTML Injection ────────────────────────────────────────────────────────────
_HTML_INJECT = [
    r"(?i)<(div|span|form|body|html|table|meta|style|textarea|select|marquee|audio|video|details)\b",
    r"(?i)<input\b",
    r"(?i)<a\s[^>]*href\s*=",
    r"(?i)<button\b",
    r"(?i)<iframe\s[^>]*src\s*=",
    r"(?i)</[a-z]+>",
]

# ── SSRF ──────────────────────────────────────────────────────────────────────
_SSRF = [
    r"(?i)file://",
    r"(?i)gopher://",
    r"(?i)ftp://",
    r"(?i)http://(127\.0\.0\.1|localhost|0\.0\.0\.0)",
    r"169\.254\.",
    r"(?i)metadata\.google\.internal",
    r"(?i)169\.254\.169\.254",
    r"(?i)kubernetes\.default\.svc",
    r"(?i)file:/etc/passwd",
    r"(?i)file:/c:/windows",
    r"(?i)http://0x7f000001",
    r"(?i)http://(10|192\.168)\.",
]

# ── CSRF markers ──────────────────────────────────────────────────────────────
_CSRF = [
    r"(?i)xsrf.token",
    r"(?i)csrf.token",
    r"(?i)Authorization:\s*Bearer\s+\S+",
    r"(?i)credentials\s*=\s*(include|same-origin|omit)",
]

# ── Path Traversal ────────────────────────────────────────────────────────────
_TRAVERSAL = [
    r"\.\./",
    r"\.\.\\",
    r"(?i)%2e%2e[%/\\]",
    r"(?i)%252e%252e",
]

# ── Command Injection ─────────────────────────────────────────────────────────
_CMD = [
    r"(?i);\s*(ls|cat|wget|curl|bash|sh|python|perl|ruby|nc|netcat)\b",
    r"\|\s*(ls|cat|wget|curl|bash|sh)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]

MALICIOUS_PATTERNS: list[re.Pattern] = [
    re.compile(p) for p in _SQL + _XSS + _HTML_INJECT + _SSRF + _CSRF + _TRAVERSAL + _CMD
]

OBFUSCATION_PATTERNS: list[re.Pattern] = [
    re.compile(p) for p in [
        r"(%[0-9A-Fa-f]{2}){2,}",
        r"(\\x[0-9A-Fa-f]{2}){2,}",
        r"(\\u[0-9A-Fa-f]{4}){2,}",
        r"(?i)\b(char|concat|substr)\s*\(",
        r"(?i)\b(base64_decode|base64_encode)\s*\(",
        r"(?i)\bfromCharCode\b",
        r"(?i)\b(decodeURIComponent|encodeURIComponent)\s*\(",
        r"(?i)\b(charCodeAt|hexToInt)\b",
        r"(?i)\bXOR\b",
        r"(?i)\b(md5|sha1|sha256)\s*\(",
        r"(?i)\bcase\s+when\b",
    ]
]


def check_signature(user_input: str) -> Literal["malicious", "obfuscated", "valid"]:
    """
    Check a raw request string against known attack and obfuscation patterns.

    Returns
    -------
    "malicious"  – direct attack detected; block immediately.
    "obfuscated" – suspicious obfuscation; pass to ML layer.
    "valid"      – nothing flagged.
    """
    normalised = " ".join(user_input.split())

    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(normalised):
            return "malicious"

    for pattern in OBFUSCATION_PATTERNS:
        if pattern.search(normalised):
            return "obfuscated"

    return "valid"