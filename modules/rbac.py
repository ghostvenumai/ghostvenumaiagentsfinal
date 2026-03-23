# modules/rbac.py — GhostVenumAI Enterprise
# Role-Based Access Control + TOTP MFA + Session Management
# ISO 27001 A.9 (Zugangssteuerung) | BSI ORP.4 (Identitäts- und Berechtigungsmanagement)
#
# Passwort-Hashing: Argon2id (OWASP 2024, BSI TR-02102-1, NIST SP 800-63b)
# Quanten-Resistenz: Argon2id ist resistenter gegen Grover-Algorithmus als PBKDF2
# Rückwärtskompatibel: Alte PBKDF2-Hashes werden beim nächsten Login automatisch migriert

import os
import json
import time
import hmac
import base64
import hashlib
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any

try:
    import pyotp
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    # BSI TR-02102-1 Empfehlung + OWASP 2024:
    # time_cost=3, memory_cost=65536 (64 MB), parallelism=4
    _ph = PasswordHasher(
        time_cost=3,         # 3 Iterationen
        memory_cost=65536,   # 64 MB RAM (macht GPU-Angriffe teuer)
        parallelism=4,       # 4 parallele Threads
        hash_len=32,         # 256-Bit Hash
        salt_len=16,         # 128-Bit Salt
    )
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

USERS_PATH   = "config.users.json"
SESSION_PATH = "logs/sessions.json"
SESSION_TTL  = 3600        # 1 Stunde (BSI-Empfehlung)
SESSION_LEN  = 64          # Bytes für Session-Token

_session_lock = threading.Lock()


# ── Rollen & Berechtigungen ───────────────────────────────────────────────────
# Prinzip der minimalen Rechte (ISO 27001 A.9.2.3)

ROLES: Dict[str, Dict[str, List[str]]] = {
    "admin": {
        "description": "Vollzugriff — Konfiguration, Benutzerverwaltung, alle Operationen",
        "permissions": [
            "scan:run", "scan:view", "scan:delete",
            "report:create", "report:view", "report:export", "report:delete",
            "config:read", "config:write",
            "monitor:start", "monitor:stop", "monitor:view",
            "history:view", "history:delete",
            "audit:view", "audit:export",
            "users:manage",
            "dsgvo:export", "dsgvo:delete", "dsgvo:retention",
            "compliance:view",
            "incident:view", "incident:create",
        ],
    },
    "analyst": {
        "description": "Sicherheitsanalyst — Scans, Reports, Monitoring (kein Admin)",
        "permissions": [
            "scan:run", "scan:view",
            "report:create", "report:view", "report:export",
            "monitor:start", "monitor:stop", "monitor:view",
            "history:view",
            "audit:view",
            "compliance:view",
            "incident:view",
        ],
    },
    "viewer": {
        "description": "Lesezugriff — nur Ansicht vorhandener Daten",
        "permissions": [
            "scan:view",
            "report:view",
            "monitor:view",
            "history:view",
            "compliance:view",
        ],
    },
    "auditor": {
        "description": "Compliance-Auditor — Audit-Log und Compliance-Berichte",
        "permissions": [
            "audit:view", "audit:export",
            "compliance:view",
            "report:view",
            "history:view",
            "dsgvo:export",
            "incident:view",
        ],
    },
}


# ── Passwort-Hashing ──────────────────────────────────────────────────────────
# Primär:   Argon2id  (post-quanten-resistent, OWASP 2024, BSI TR-02102-1)
# Fallback: PBKDF2-HMAC-SHA256 (für alte Passwörter — werden automatisch migriert)

def _hash_password(password: str) -> Dict[str, str]:
    """Erstellt Argon2id-Hash (bevorzugt) oder PBKDF2-Fallback."""
    if ARGON2_AVAILABLE:
        h = _ph.hash(password)
        return {
            "hash": h,
            "algo": "Argon2id",
            # Parameter sind im Hash kodiert — kein separates Salt nötig
        }
    # Fallback: PBKDF2 (wenn argon2-cffi nicht installiert)
    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return {
        "hash":  derived.hex(),
        "salt":  salt.hex(),
        "iter":  600000,
        "algo":  "PBKDF2-HMAC-SHA256",
    }


def _verify_password(password: str, stored: Dict[str, str]) -> bool:
    """
    Verifiziert Passwort gegen gespeicherten Hash.
    Unterstützt Argon2id (neu) und PBKDF2 (legacy) automatisch.
    """
    algo = stored.get("algo", "PBKDF2-HMAC-SHA256")

    if algo == "Argon2id" and ARGON2_AVAILABLE:
        try:
            return _ph.verify(stored["hash"], password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    # PBKDF2-Fallback für alte Passwörter
    try:
        salt       = bytes.fromhex(stored["salt"])
        iterations = stored.get("iter", 600_000)
        derived    = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(derived, bytes.fromhex(stored["hash"]))
    except Exception:
        return False


def _needs_rehash(stored: Dict[str, str]) -> bool:
    """Prüft ob ein Hash auf Argon2id migriert werden sollte."""
    if not ARGON2_AVAILABLE:
        return False
    if stored.get("algo") != "Argon2id":
        return True
    # Argon2id-interne Prüfung ob Parameter veraltet sind
    try:
        return _ph.check_needs_rehash(stored["hash"])
    except Exception:
        return False


# ── Benutzerverwaltung ────────────────────────────────────────────────────────

def _load_users() -> Dict[str, Any]:
    if not os.path.exists(USERS_PATH):
        return {}
    try:
        with open(USERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_users(users: Dict[str, Any]) -> None:
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_PATH)
    try:
        os.chmod(USERS_PATH, 0o600)
    except Exception:
        pass


def create_user(username: str, password: str, role: str = "viewer",
                created_by: str = "system") -> Dict[str, Any]:
    """Erstellt einen neuen Benutzer."""
    if role not in ROLES:
        raise ValueError(f"Unbekannte Rolle: {role}. Gültige Rollen: {list(ROLES.keys())}")

    users = _load_users()
    if username in users:
        raise ValueError(f"Benutzer '{username}' existiert bereits.")

    pw_data = _hash_password(password)
    user    = {
        "username":   username,
        "role":       role,
        "password":   pw_data,
        "totp_secret": None,
        "totp_enabled": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": created_by,
        "last_login": None,
        "active":     True,
        "login_count": 0,
    }

    users[username] = user
    _save_users(users)

    try:
        from modules.audit_logger import log_auth
        log_auth("user_created", username, "success",
                 details={"role": role, "created_by": created_by})
    except Exception:
        pass

    return {"username": username, "role": role, "totp_enabled": False}


def delete_user(username: str, deleted_by: str = "admin") -> bool:
    users = _load_users()
    if username not in users:
        return False
    del users[username]
    _save_users(users)

    try:
        from modules.audit_logger import log_auth
        log_auth("user_deleted", username, "success",
                 details={"deleted_by": deleted_by})
    except Exception:
        pass
    return True


def list_users() -> List[Dict[str, Any]]:
    users = _load_users()
    return [
        {
            "username":     u["username"],
            "role":         u["role"],
            "active":       u["active"],
            "totp_enabled": u["totp_enabled"],
            "created_at":   u["created_at"],
            "last_login":   u["last_login"],
            "login_count":  u.get("login_count", 0),
        }
        for u in users.values()
    ]


def init_default_admin(password: str) -> None:
    """Erstellt den Standard-Admin-Benutzer (einmalig bei Setup)."""
    users = _load_users()
    if "admin" in users:
        return
    create_user("admin", password, role="admin", created_by="system_init")
    print("[RBAC] Admin-Benutzer erstellt.")


# ── TOTP / MFA ────────────────────────────────────────────────────────────────
# ISO 27001 A.9.4.2 — Sichere Anmeldeverfahren
# BSI M 4.133 — Zwei-Faktor-Authentisierung

def setup_totp(username: str) -> Optional[Dict[str, str]]:
    """Richtet TOTP-MFA für einen Benutzer ein. Gibt Secret + QR-URI zurück."""
    if not TOTP_AVAILABLE:
        return {"error": "pyotp nicht installiert. pip install pyotp"}

    users = _load_users()
    if username not in users:
        return None

    secret = pyotp.random_base32()
    users[username]["totp_secret"]  = secret
    users[username]["totp_enabled"] = False  # Erst nach Verifikation aktivieren
    _save_users(users)

    totp    = pyotp.TOTP(secret)
    uri     = totp.provisioning_uri(name=username, issuer_name="GhostVenumAI")

    return {
        "secret":   secret,
        "uri":      uri,
        "message":  "QR-Code in Authenticator-App einscannen, dann verify_totp aufrufen.",
    }


def verify_and_activate_totp(username: str, code: str) -> bool:
    """Verifiziert TOTP-Code und aktiviert MFA nach erstem Scan."""
    if not TOTP_AVAILABLE:
        return False

    users = _load_users()
    user  = users.get(username)
    if not user or not user.get("totp_secret"):
        return False

    totp = pyotp.TOTP(user["totp_secret"])
    if totp.verify(code, valid_window=1):
        users[username]["totp_enabled"] = True
        _save_users(users)
        return True
    return False


def _verify_totp(username: str, code: str) -> bool:
    if not TOTP_AVAILABLE:
        return True   # Wenn pyotp fehlt, TOTP überspringen (warnen)

    users = _load_users()
    user  = users.get(username)
    if not user or not user.get("totp_enabled") or not user.get("totp_secret"):
        return True   # TOTP nicht aktiviert → erlaubt

    totp = pyotp.TOTP(user["totp_secret"])
    return totp.verify(code, valid_window=1)


# ── Session Management ─────────────────────────────────────────────────────────

def _load_sessions() -> Dict[str, Any]:
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(SESSION_PATH):
        return {}
    try:
        with open(SESSION_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_sessions(sessions: Dict[str, Any]) -> None:
    tmp = SESSION_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2, ensure_ascii=False)
    os.replace(tmp, SESSION_PATH)
    try:
        os.chmod(SESSION_PATH, 0o600)
    except Exception:
        pass


def _purge_expired_sessions(sessions: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    return {
        token: data
        for token, data in sessions.items()
        if data.get("expires_at", 0) > now
    }


# ── Authentifizierung ─────────────────────────────────────────────────────────

def authenticate(username: str, password: str,
                 totp_code: str = "",
                 source_ip: str = "127.0.0.1") -> Optional[str]:
    """
    Authentifiziert Benutzer (Passwort + optional TOTP).
    Gibt Session-Token zurück oder None bei Fehler.
    """
    users = _load_users()
    user  = users.get(username)

    if not user or not user.get("active"):
        _audit_auth(username, "login", "failure_unknown_user", source_ip)
        return None

    if not _verify_password(password, user["password"]):
        _audit_auth(username, "login", "failure_wrong_password", source_ip)
        return None

    # ── Automatische Hash-Migration: PBKDF2 → Argon2id ───────────────────────
    # Beim erfolgreichen Login wird der alte Hash transparent ersetzt
    if _needs_rehash(user["password"]):
        try:
            users[username]["password"] = _hash_password(password)
            users[username]["pw_algo_upgraded"] = datetime.now(timezone.utc).isoformat()
            _save_users(users)
            _audit_auth(username, "password_rehash", "success", source_ip,
                        {"from": user["password"].get("algo","PBKDF2"), "to": "Argon2id"})
        except Exception:
            pass  # Migration fehlgeschlagen — Login trotzdem erlaubt

    if user.get("totp_enabled") and not _verify_totp(username, totp_code):
        _audit_auth(username, "login", "failure_totp_invalid", source_ip)
        return None

    # Session erstellen
    token      = secrets.token_hex(SESSION_LEN)
    expires_at = time.time() + SESSION_TTL

    with _session_lock:
        sessions = _load_sessions()
        sessions = _purge_expired_sessions(sessions)
        sessions[token] = {
            "username":   username,
            "role":       user["role"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at,
            "source_ip":  source_ip,
        }
        _save_sessions(sessions)

    # Login-Statistik
    users[username]["last_login"]  = datetime.now(timezone.utc).isoformat()
    users[username]["login_count"] = users[username].get("login_count", 0) + 1
    _save_users(users)

    _audit_auth(username, "login", "success", source_ip,
                {"role": user["role"], "totp_used": bool(totp_code)})
    return token


def logout(token: str) -> bool:
    with _session_lock:
        sessions = _load_sessions()
        if token in sessions:
            user = sessions[token].get("username", "?")
            del sessions[token]
            _save_sessions(sessions)
            _audit_auth(user, "logout", "success", "127.0.0.1")
            return True
    return False


def get_session(token: str) -> Optional[Dict[str, Any]]:
    """Gibt Session-Daten zurück oder None wenn abgelaufen/ungültig."""
    if not token:
        return None
    with _session_lock:
        sessions = _load_sessions()
        session  = sessions.get(token)
        if not session:
            return None
        if session["expires_at"] < time.time():
            del sessions[token]
            _save_sessions(sessions)
            return None
        # Session verlängern bei Aktivität (Sliding Window)
        sessions[token]["expires_at"] = time.time() + SESSION_TTL
        _save_sessions(sessions)
        return session


# ── Berechtigungsprüfung ──────────────────────────────────────────────────────

def has_permission(token: str, permission: str) -> bool:
    """Prüft ob Session die angegebene Berechtigung hat."""
    session = get_session(token)
    if not session:
        return False
    role  = session.get("role", "viewer")
    perms = ROLES.get(role, {}).get("permissions", [])
    return permission in perms


def require_permission(token: str, permission: str) -> Dict[str, Any]:
    """
    Gibt Session zurück wenn berechtigt, sonst Exception.
    Für Flask-Route-Decorator-Nutzung.
    """
    session = get_session(token)
    if not session:
        raise PermissionError("Nicht authentifiziert oder Session abgelaufen.")
    if not has_permission(token, permission):
        raise PermissionError(
            f"Keine Berechtigung: '{permission}' "
            f"(Rolle: {session.get('role', '?')})"
        )
    return session


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _audit_auth(username: str, action: str, result: str,
                source_ip: str, details: dict = None):
    try:
        from modules.audit_logger import log_auth
        log_auth(action, username, result, source_ip, details or {})
    except Exception:
        pass


def get_roles_overview() -> Dict[str, Any]:
    return {
        role: {
            "description":       data["description"],
            "permission_count":  len(data["permissions"]),
            "permissions":       data["permissions"],
        }
        for role, data in ROLES.items()
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import getpass

    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "create-user":
        uname = sys.argv[2] if len(sys.argv) > 2 else input("Benutzername: ")
        role  = sys.argv[3] if len(sys.argv) > 3 else "analyst"
        pw    = getpass.getpass("Passwort: ")
        result = create_user(uname, pw, role)
        print(f"✅ Benutzer erstellt: {json.dumps(result, indent=2)}")

    elif cmd == "list-users":
        for u in list_users():
            print(f"  {u['username']:20} [{u['role']:10}] "
                  f"TOTP={'✓' if u['totp_enabled'] else '✗'} "
                  f"Active={'✓' if u['active'] else '✗'}")

    elif cmd == "setup-totp":
        uname = sys.argv[2] if len(sys.argv) > 2 else input("Benutzername: ")
        result = setup_totp(uname)
        if result:
            print(f"TOTP Secret: {result['secret']}")
            print(f"URI für Authenticator-App:\n{result['uri']}")
        else:
            print("Fehler: Benutzer nicht gefunden oder pyotp fehlt.")

    elif cmd == "roles":
        for role, data in get_roles_overview().items():
            print(f"\n[{role.upper()}] {data['description']}")
            for p in data['permissions']:
                print(f"  • {p}")

    elif cmd == "init-admin":
        pw = getpass.getpass("Admin-Passwort festlegen: ")
        pw2 = getpass.getpass("Wiederholen: ")
        if pw != pw2:
            print("Passwörter stimmen nicht überein.")
            sys.exit(1)
        init_default_admin(pw)

    else:
        print("Befehle: create-user [name] [role] | list-users | setup-totp [name] | roles | init-admin")
