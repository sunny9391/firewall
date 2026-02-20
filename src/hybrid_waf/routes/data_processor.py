import os
import re

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'logs', 'detections.log')

_LINE_RE     = re.compile(r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+-\s+(.*?)\s+-\s+(\S.*?)$")
_DECISION_RE = re.compile(r"^(\w+)(?:\(([^)]+)\))?")
_URI_RE      = re.compile(r"URI:(\S+)")
_IP_RE       = re.compile(r"IP:(\S+)")
_METHOD_RE   = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")


def _classify_attack(request_info: str) -> str:
    t = request_info.lower()
    if any(k in t for k in ("union", "select", "drop", "insert", "delete", "sleep(", "waitfor")):
        return "SQL Injection"
    if any(k in t for k in ("<script", "alert(", "onerror=", "onload=", "javascript:")):
        return "XSS"
    if any(k in t for k in ("../", "..%2f", "%2e%2e")):
        return "Path Traversal"
    if any(k in t for k in ("file://", "gopher://", "http://127.", "169.254")):
        return "SSRF"
    if any(k in t for k in (";ls", ";cat", "|bash", "`")):
        return "Command Injection"
    if any(k in t for k in ("%2", "%3", "\\x", "\\u")):
        return "Obfuscated"
    return "Unknown"


def parse_log_entry(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None

    timestamp, request_info, decision_raw = m.group(1), m.group(2), m.group(3)

    dm     = _DECISION_RE.match(decision_raw.strip())
    status = dm.group(1).lower() if dm else "unknown"
    reason = (dm.group(2) or "N/A").upper() if dm else "N/A"

    ip_m     = _IP_RE.search(request_info)
    uri_m    = _URI_RE.search(request_info)
    method_m = _METHOD_RE.search(request_info)

    ip     = ip_m.group(1) if ip_m else "N/A"
    path   = uri_m.group(1) if uri_m else (request_info.strip()[:80] or "/")
    method = method_m.group(1) if method_m else "GET"

    attack_type = _classify_attack(request_info) if status == "malicious" else "N/A"

    return {
        'timestamp':   timestamp,
        'method':      method,
        'path':        path,
        'status':      status,
        'reason':      reason,
        'ip':          ip,
        'attack_type': attack_type,
    }


def get_all_waf_logs() -> list[dict]:
    logs = []
    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                entry = parse_log_entry(line)
                if entry:
                    logs.append(entry)
    except FileNotFoundError:
        pass
    return logs