# modules/audit_logger.py — GhostVenumAI Enterprise
# Manipulationssicheres Audit-Logging mit HMAC-Kette
# ISO 27001 A.12.4 (Protokollierung) | BSI OPS.1.1.5 | BSI SYS.1.1 A.9
#
# HMAC-Kette: Jeder Eintrag enthält HMAC(prev_hash || entry_json)
# → Nachträgliche Manipulation wird bei Verifikation erkannt

import os
import json
import time
import hmac
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum

LOG_DIR       = "logs"
AUDIT_LOG     = os.path.join(LOG_DIR, "audit.jsonl")      # Haupt-Audit-Log
CHAIN_STATE   = os.path.join(LOG_DIR, "audit.chain")      # Letzter Hash der Kette
ROTATION_MAX  = 10 * 1024 * 1024   # 10 MB vor Rotation
HMAC_KEY_ENV  = "AUDIT_HMAC_KEY"   # Optionaler externer HMAC-Schlüssel

_lock = threading.Lock()


class AuditLevel(str, Enum):
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARN     = "WARN"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"
    AUDIT    = "AUDIT"     # Sicherheitsereignisse (immer persistiert)
    SECURITY = "SECURITY"  # Authentifizierung, Autorisierung


class AuditCategory(str, Enum):
    AUTH          = "AUTH"           # An-/Abmeldung, MFA
    ACCESS        = "ACCESS"         # Ressourcenzugriff
    DATA          = "DATA"           # Datenzugriff, -export, -löschung
    SCAN          = "SCAN"           # Netzwerk-Scan-Operationen
    CONFIG        = "CONFIG"         # Konfigurationsänderungen
    INCIDENT      = "INCIDENT"       # Sicherheitsvorfälle
    COMPLIANCE    = "COMPLIANCE"     # Compliance-Ereignisse
    SYSTEM        = "SYSTEM"         # Systemstart/-stop, Fehler
    API           = "API"            # Externe API-Aufrufe
    KEY_MGMT      = "KEY_MGMT"       # Schlüsselverwaltung
    REPORT        = "REPORT"         # Berichterstellung/-export


# ── HMAC-Schlüssel ─────────────────────────────────────────────────────────────

def _get_hmac_key() -> bytes:
    """Gibt den HMAC-Schlüssel zurück (env → generiert + persistiert)."""
    env_key = os.environ.get(HMAC_KEY_ENV)
    if env_key:
        return bytes.fromhex(env_key)

    key_file = os.path.join(LOG_DIR, ".audit_hmac_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return bytes.fromhex(f.read().strip())

    # Einmalig generieren und sicher speichern
    os.makedirs(LOG_DIR, exist_ok=True)
    key = secrets.token_bytes(32)
    with open(key_file, "w") as f:
        f.write(key.hex())
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return key


def _hmac_sign(data: str, prev_hash: str) -> str:
    """Erstellt HMAC über vorherigen Hash + aktuellen Eintrag (Kette)."""
    key     = _get_hmac_key()
    message = (prev_hash + data).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ── Kettenzustand ─────────────────────────────────────────────────────────────

def _load_chain_hash() -> str:
    if os.path.exists(CHAIN_STATE):
        try:
            with open(CHAIN_STATE, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return "GENESIS"


def _save_chain_hash(h: str) -> None:
    with open(CHAIN_STATE, "w") as f:
        f.write(h)
    try:
        os.chmod(CHAIN_STATE, 0o600)
    except Exception:
        pass


# ── Log-Rotation ───────────────────────────────────────────────────────────────

def _rotate_if_needed() -> None:
    if not os.path.exists(AUDIT_LOG):
        return
    if os.path.getsize(AUDIT_LOG) < ROTATION_MAX:
        return

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive  = AUDIT_LOG.replace(".jsonl", f"_{ts}.jsonl")
    os.rename(AUDIT_LOG, archive)


# ── Kern-Logging ───────────────────────────────────────────────────────────────

def log(
    level:     AuditLevel,
    category:  AuditCategory,
    action:    str,
    details:   Optional[Dict[str, Any]] = None,
    user:      str = "system",
    source_ip: str = "127.0.0.1",
    result:    str = "success",
) -> str:
    """
    Schreibt einen Audit-Log-Eintrag mit HMAC-Kettenintegration.
    Gibt die Eintrags-ID zurück.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    entry_id = secrets.token_hex(8)
    ts_iso   = datetime.now(timezone.utc).isoformat()

    entry = {
        "id":        entry_id,
        "timestamp": ts_iso,
        "level":     level.value,
        "category":  category.value,
        "action":    action,
        "user":      user,
        "source_ip": source_ip,
        "result":    result,
        "details":   details or {},
    }

    entry_json = json.dumps(entry, ensure_ascii=False, sort_keys=True)

    with _lock:
        _rotate_if_needed()
        prev_hash      = _load_chain_hash()
        entry["hmac"]  = _hmac_sign(entry_json, prev_hash)
        entry["prev"]  = prev_hash

        final_json = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        new_hash   = hashlib.sha256(final_json.encode("utf-8")).hexdigest()

        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(final_json + "\n")

        _save_chain_hash(new_hash)

    return entry_id


# ── Convenience-Funktionen ────────────────────────────────────────────────────

def log_auth(action: str, user: str, result: str, source_ip: str = "127.0.0.1", details: dict = None):
    return log(AuditLevel.SECURITY, AuditCategory.AUTH, action, details, user, source_ip, result)

def log_access(action: str, user: str, resource: str, result: str = "success"):
    return log(AuditLevel.AUDIT, AuditCategory.ACCESS, action,
               {"resource": resource}, user, "127.0.0.1", result)

def log_scan(target: str, user: str = "system", scan_args: str = ""):
    return log(AuditLevel.AUDIT, AuditCategory.SCAN, "network_scan_started",
               {"target": target, "nmap_args": scan_args}, user, "127.0.0.1", "initiated")

def log_scan_complete(target: str, port_count: int, cve_count: int, user: str = "system"):
    return log(AuditLevel.AUDIT, AuditCategory.SCAN, "network_scan_completed",
               {"target": target, "ports_found": port_count, "cves_found": cve_count},
               user, "127.0.0.1", "success")

def log_data_export(data_type: str, user: str, format_: str = "pdf"):
    return log(AuditLevel.AUDIT, AuditCategory.DATA, "data_export",
               {"data_type": data_type, "format": format_}, user, "127.0.0.1", "success")

def log_data_deletion(data_type: str, user: str, reason: str = "retention_policy"):
    return log(AuditLevel.AUDIT, AuditCategory.DATA, "data_deletion",
               {"data_type": data_type, "reason": reason}, user, "127.0.0.1", "success")

def log_config_change(field: str, user: str, old_value: str = "REDACTED", new_value: str = "REDACTED"):
    return log(AuditLevel.AUDIT, AuditCategory.CONFIG, "config_changed",
               {"field": field, "old": old_value, "new": new_value}, user, "127.0.0.1", "success")

def log_incident(severity: str, description: str, details: dict = None):
    level = AuditLevel.CRITICAL if severity in ("high", "critical") else AuditLevel.WARN
    return log(level, AuditCategory.INCIDENT, "security_incident",
               {"severity": severity, "description": description, **(details or {})},
               "system", "127.0.0.1", "detected")

def log_api_call(api_name: str, endpoint: str, user: str = "system", success: bool = True):
    return log(AuditLevel.INFO, AuditCategory.API, "external_api_call",
               {"api": api_name, "endpoint": endpoint}, user, "127.0.0.1",
               "success" if success else "failure")

def log_system_event(action: str, details: dict = None):
    return log(AuditLevel.INFO, AuditCategory.SYSTEM, action, details,
               "system", "127.0.0.1", "success")


# ── Verifikation ───────────────────────────────────────────────────────────────

def verify_chain() -> Dict[str, Any]:
    """
    Prüft die HMAC-Kette auf Manipulation.
    Gibt Bericht mit Status und erstem fehlerhaften Eintrag zurück.
    """
    if not os.path.exists(AUDIT_LOG):
        return {"valid": True, "entries": 0, "message": "Kein Log vorhanden."}

    key          = _get_hmac_key()
    prev_hash    = "GENESIS"
    total        = 0
    errors       = []

    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                total += 1

                stored_hmac  = entry.pop("hmac", "")
                stored_prev  = entry.pop("prev", "")
                entry_json   = json.dumps(entry, ensure_ascii=False, sort_keys=True)

                expected_hmac = hmac.new(
                    key,
                    (stored_prev + entry_json).encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(stored_hmac, expected_hmac):
                    errors.append({
                        "line": lineno,
                        "id":   entry.get("id", "?"),
                        "ts":   entry.get("timestamp", "?"),
                        "error": "HMAC-Mismatch — mögliche Manipulation!",
                    })

                if stored_prev != prev_hash:
                    errors.append({
                        "line": lineno,
                        "id":   entry.get("id", "?"),
                        "ts":   entry.get("timestamp", "?"),
                        "error": "Kettenbruch — Eintrag fehlt oder wurde eingefügt!",
                    })

                # Hash für nächste Iteration
                entry["hmac"] = stored_hmac
                entry["prev"] = stored_prev
                full_json     = json.dumps(entry, ensure_ascii=False, sort_keys=True)
                prev_hash     = hashlib.sha256(full_json.encode("utf-8")).hexdigest()

            except json.JSONDecodeError:
                errors.append({"line": lineno, "error": "Ungültiges JSON"})

    return {
        "valid":   len(errors) == 0,
        "entries": total,
        "errors":  errors,
        "message": "Integritätsprüfung erfolgreich." if not errors else f"{len(errors)} Fehler gefunden!",
    }


# ── Abfrage / Export ──────────────────────────────────────────────────────────

def read_recent(n: int = 50, level_filter: Optional[str] = None,
                category_filter: Optional[str] = None) -> List[Dict]:
    """Gibt die letzten n Audit-Einträge zurück (optional gefiltert)."""
    if not os.path.exists(AUDIT_LOG):
        return []

    entries = []
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if level_filter    and e.get("level")    != level_filter:
                    continue
                if category_filter and e.get("category") != category_filter:
                    continue
                entries.append(e)
            except Exception:
                pass

    return entries[-n:]


def export_audit_log(output_path: str, since_iso: Optional[str] = None) -> int:
    """Exportiert das Audit-Log (DSGVO Art. 30, ISO 27001 A.12.4)."""
    entries = read_recent(n=999_999)
    if since_iso:
        entries = [e for e in entries if e.get("timestamp", "") >= since_iso]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    log_data_export("audit_log", user="system", format_="json")
    return len(entries)


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "tail"

    if cmd == "verify":
        result = verify_chain()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result["valid"] else 1)
    elif cmd == "tail":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        for e in read_recent(n):
            print(f"[{e['timestamp']}] [{e['level']:8}] [{e['category']:12}] {e['action']} — {e.get('result','')}")
    elif cmd == "export":
        path = sys.argv[2] if len(sys.argv) > 2 else "audit_export.json"
        count = export_audit_log(path)
        print(f"✅ {count} Einträge exportiert nach: {path}")
    else:
        print("Befehle: verify | tail [N] | export [output.json]")
