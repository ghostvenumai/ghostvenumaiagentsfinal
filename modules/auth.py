# modules/auth.py
import os
import sys
import json
import time
import getpass
import hashlib
import hmac
import secrets
from typing import List, Dict, Any

CFG_PATH = "config.json"
LOG_DIR  = "logs"
ATTEMPT_LOG = os.path.join(LOG_DIR, "auth_attempts.json")

WINDOW_SEC             = 30 * 60
BASE_DELAY             = 2
MAX_DELAY              = 60
JITTER_FRAC            = 0.15
DECAY_SUCCESS          = True
MAX_TRIES_PER_SESSION  = 3

def is_ssh_session() -> bool:
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"):
        return True
    try:
        return sys.stdin.isatty()
    except Exception:
        return False

def _load_cfg() -> Dict[str, Any]:
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _pbkdf2_hash(password: str, salt: bytes, rounds: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)

def _safe_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def _ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)

def _load_attempts() -> List[Dict[str, Any]]:
    _ensure_dirs()
    if not os.path.exists(ATTEMPT_LOG):
        return []
    try:
        with open(ATTEMPT_LOG, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_attempts(atts: List[Dict[str, Any]]):
    _ensure_dirs()
    tmp = ATTEMPT_LOG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(atts, f, ensure_ascii=False, indent=2)
    os.replace(tmp, ATTEMPT_LOG)

def _prune_old(atts: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
    cutoff = now - WINDOW_SEC
    return [a for a in atts if a.get("ts", 0) >= cutoff]

def _count_recent_failures(atts: List[Dict[str, Any]], now: float) -> int:
    recent = _prune_old(atts, now)
    return sum(1 for a in recent if a.get("ok") is False)

def _record_attempt(ok: bool, now: float):
    atts = _load_attempts()
    atts = _prune_old(atts, now)
    atts.append({"ts": now, "ok": bool(ok)})
    _save_attempts(atts)

def _clear_failures():
    if DECAY_SUCCESS and os.path.exists(ATTEMPT_LOG):
        try:
            os.remove(ATTEMPT_LOG)
        except Exception:
            pass

def _sleep_with_jitter(seconds: float):
    import random
    jitter = seconds * JITTER_FRAC
    delay = max(0.0, seconds + random.uniform(-jitter, jitter))
    time.sleep(delay)

def _progressive_delay(recent_fails: int):
    if recent_fails <= 0:
        return
    delay = min(MAX_DELAY, BASE_DELAY * (2 ** (recent_fails - 1)))
    print(f"[⏳] Anti-Brute-Force aktiv – Warte {int(delay)}s (Fehlversuche: {recent_fails})...")
    _sleep_with_jitter(delay)

def require_password(max_tries: int = MAX_TRIES_PER_SESSION) -> bool:
    """
    Passwortabfrage mit PBKDF2-HMAC-SHA256 und Anti-Brute-Force-Backoff.
    """
    cfg = _load_cfg()
    hash_hex = cfg.get("ssh_password_hash")
    salt_hex = cfg.get("ssh_password_salt")
    plain_pw = cfg.get("ssh_password")

    if not (hash_hex and salt_hex) and plain_pw is None:
        print("[!] Keine Passwortkonfiguration gefunden. Zugriff verweigert.")
        return False

    for attempt in range(1, max_tries + 1):
        now = time.time()
        recent_fails = _count_recent_failures(_load_attempts(), now)
        _progressive_delay(recent_fails)

        try:
            entered = getpass.getpass("🔐 SSH erkannt – bitte Passwort eingeben: ")
        except Exception:
            print("Fehler bei der Passwortabfrage.")
            return False

        ok = False
        if hash_hex and salt_hex:
            try:
                salt     = bytes.fromhex(salt_hex)
                expected = bytes.fromhex(hash_hex)
                derived  = _pbkdf2_hash(entered, salt)
                ok       = _safe_compare(derived, expected)
            except Exception as e:
                print(f"[!] Hash-Prüfung fehlgeschlagen: {e}")
                return False
        elif plain_pw is not None:
            ok = (entered == str(plain_pw))

        _record_attempt(ok=ok, now=now)

        if ok:
            print("[✅] Zugriff gewährt.")
            _clear_failures()
            return True
        else:
            remaining = max_tries - attempt
            if remaining > 0:
                print(f"[❌] Falsches Passwort. Verbleibende Versuche: {remaining}")
            else:
                print("[❌] Keine Versuche mehr in dieser Session.")

    return False

def _gen_hash_cli():
    pw1 = getpass.getpass("Neues Passwort: ")
    pw2 = getpass.getpass("Passwort wiederholen: ")
    if pw1 != pw2:
        print("Passwörter stimmen nicht überein.")
        sys.exit(1)
    salt    = secrets.token_bytes(16)
    derived = _pbkdf2_hash(pw1, salt)
    out     = {"ssh_password_salt": salt.hex(), "ssh_password_hash": derived.hex()}
    print("\nIn config.json einfügen (ssh_password entfernen):")
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    _gen_hash_cli()
