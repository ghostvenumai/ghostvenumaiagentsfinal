# modules/security_headers.py — GhostVenumAI Enterprise
# HTTP Security Headers & Rate Limiting Middleware
# OWASP Top 10 | BSI APP.3.1 (Web-Anwendungen) | ISO 27001 A.14

from flask import request, jsonify, g
from functools import wraps
import time
import threading
from typing import Dict, Tuple, Optional, Callable
import os

# ── Rate Limiter ──────────────────────────────────────────────────────────────
# BSI APP.3.1.A6 — Schutz vor unerlaubter automatisierter Nutzung

_rate_store: Dict[str, Tuple[int, float]] = {}   # {ip: (count, window_start)}
_rate_lock  = threading.Lock()

RATE_LIMITS = {
    "default":  (60,  60),    # 60 Anfragen / 60 Sekunden
    "scan":     (10,  60),    # 10 Scans / Minute (ressourcenintensiv)
    "auth":     (5,   300),   # 5 Auth-Versuche / 5 Minuten
    "export":   (5,   60),    # 5 Exporte / Minute
}


def _get_client_ip() -> str:
    """Ermittelt echte Client-IP (auch hinter Proxy)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def rate_limit(limit_type: str = "default"):
    """Decorator: Rate-Limiting für Flask-Routen."""
    max_requests, window_sec = RATE_LIMITS.get(limit_type, RATE_LIMITS["default"])

    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip  = _get_client_ip()
            key = f"{ip}:{limit_type}"
            now = time.time()

            with _rate_lock:
                count, window_start = _rate_store.get(key, (0, now))

                if now - window_start > window_sec:
                    count        = 0
                    window_start = now

                count += 1
                _rate_store[key] = (count, window_start)

                if count > max_requests:
                    reset_in = int(window_sec - (now - window_start))
                    try:
                        from modules.audit_logger import log_incident
                        log_incident("medium", f"Rate-Limit überschritten von {ip} [{limit_type}]",
                                     {"ip": ip, "count": count, "limit": max_requests})
                    except Exception:
                        pass
                    response = jsonify({
                        "error":     "Rate-Limit überschritten.",
                        "limit":     max_requests,
                        "window_sec": window_sec,
                        "retry_in":  reset_in,
                    })
                    response.status_code = 429
                    response.headers["Retry-After"] = str(reset_in)
                    return response

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── API Token Authentifizierung ───────────────────────────────────────────────
# ISO 27001 A.9.4.2 | BSI APP.3.1.A3

def require_auth(permission: str = "scan:view"):
    """Decorator: Session-Token-Prüfung für Flask-Routen."""
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Kein Auth in Entwicklungsmodus (localhost only)
            if os.environ.get("GHOSTVENUM_DEV_MODE") == "1":
                g.session = {"username": "dev", "role": "admin"}
                return f(*args, **kwargs)

            token = (
                request.headers.get("X-Session-Token") or
                request.cookies.get("session_token") or
                request.args.get("token")
            )

            if not token:
                return jsonify({"error": "Authentifizierung erforderlich.", "code": "NO_TOKEN"}), 401

            try:
                from modules.rbac import require_permission
                session = require_permission(token, permission)
                g.session = session
            except PermissionError as e:
                try:
                    from modules.audit_logger import log_access
                    log_access("unauthorized_access", "unknown", permission, "denied")
                except Exception:
                    pass
                return jsonify({"error": str(e), "code": "FORBIDDEN"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Security Headers ───────────────────────────────────────────────────────────
# OWASP Secure Headers | BSI APP.3.1.A1

def add_security_headers(response):
    """
    Fügt HTTP Security Headers zu jeder Antwort hinzu.
    Flask after_request Handler.
    """
    # Content Security Policy (XSS-Schutz)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "   # inline JS für SSE
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # Clickjacking-Schutz
    response.headers["X-Frame-Options"] = "DENY"

    # MIME-Type-Sniffing verhindern
    response.headers["X-Content-Type-Options"] = "nosniff"

    # XSS-Filter (Legacy-Browser)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer-Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions Policy (Browser-Features einschränken)
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), "
        "payment=(), usb=(), bluetooth=()"
    )

    # HSTS (nur wenn HTTPS aktiv)
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    # Server-Header entfernen (Informationsminimierung)
    response.headers.pop("Server", None)

    # Cache-Control für API-Antworten
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"]         = "no-cache"

    return response


# ── Input-Validierung ─────────────────────────────────────────────────────────
# OWASP A03:2021 Injection | BSI APP.3.1.A10

import re

def validate_ip_or_range(value: str) -> Tuple[bool, str]:
    """
    Validiert IP-Adresse oder CIDR-Range.
    Verhindert Command-Injection in Nmap-Argumente.
    """
    if not value or len(value) > 100:
        return False, "Ungültige Eingabe (leer oder zu lang)"

    # Erlaubte Formate:
    # IPv4: 192.168.1.1
    # IPv4-CIDR: 192.168.1.0/24
    # IPv4-Range: 192.168.1.1-254
    # Hostname: server.example.com
    # Keine Shell-Sonderzeichen!
    dangerous = re.search(r'[;&|`$\\<>()\n\r\t\'"!{}\[\]]', value)
    if dangerous:
        return False, f"Ungültiges Zeichen in Eingabe: '{dangerous.group()}'"

    # IP-Pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?(-\d{1,3})?$'
    host_pattern = r'^[a-zA-Z0-9._-]+$'
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'

    if (re.match(ip_pattern, value) or
        re.match(host_pattern, value) or
        re.match(range_pattern, value)):
        return True, "OK"

    return False, "Unbekanntes IP/Hostname-Format"


def validate_nmap_args(args: str) -> Tuple[bool, str]:
    """
    Validiert Nmap-Argumente gegen Whitelist erlaubter Flags.
    Verhindert Command-Injection.
    """
    if not args:
        return True, "OK (leer)"

    if len(args) > 500:
        return False, "Argumente zu lang (max. 500 Zeichen)"

    # Gefährliche Shell-Sequenzen
    dangerous = re.search(r'[;&|`$\\<>()\n\r\'"{}\[\]!]', args)
    if dangerous:
        return False, f"Ungültiges Zeichen: '{dangerous.group()}'"

    # Whitelist erlaubter Nmap-Flags
    allowed_flags = {
        "-sS", "-sT", "-sU", "-sV", "-sC", "-sn", "-sP",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-p", "--open", "--top-ports",
        "-v", "-vv", "-A", "-O",
        "--script", "-oN", "-oX",
        "-Pn", "-n", "--host-timeout",
    }

    parts = args.split()
    for part in parts:
        if part.startswith("-"):
            base = part.split("=")[0]
            if base not in allowed_flags and not re.match(r'^-p\d', part):
                return False, f"Nicht erlaubtes Nmap-Flag: '{part}'"

    return True, "OK"


def sanitize_string(value: str, max_len: int = 256) -> str:
    """Bereinigt Strings für sichere Nutzung."""
    if not isinstance(value, str):
        return ""
    # Steuerzeichen entfernen
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    return value[:max_len].strip()


# ── CORS-Einschränkung ─────────────────────────────────────────────────────────

def configure_cors(app, allowed_origins: Optional[list] = None):
    """
    Konfiguriert CORS sicher — nur localhost standardmäßig.
    BSI APP.3.1.A1 — Authentifizierung bei Web-Anwendungen.
    """
    if allowed_origins is None:
        allowed_origins = ["http://localhost:5000", "http://127.0.0.1:5000"]

    from flask_cors import CORS
    CORS(app,
         origins=allowed_origins,
         supports_credentials=True,
         allow_headers=["Content-Type", "X-Session-Token"],
         methods=["GET", "POST", "OPTIONS"])
