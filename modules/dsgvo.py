# modules/dsgvo.py — GhostVenumAI Enterprise
# DSGVO / GDPR Compliance Manager
# Art. 5 (Grundsätze), Art. 17 (Recht auf Löschung), Art. 20 (Datenportabilität)
# Art. 30 (Verarbeitungsverzeichnis), Art. 33/34 (Meldepflicht Datenpannen)
# Art. 35 (Datenschutz-Folgenabschätzung, DSFA)

import os
import json
import time
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any
from pathlib import Path

# Verzeichnisse
OUTPUT_DIR  = "output"
HISTORY_DIR = os.path.join(OUTPUT_DIR, "history")
LOG_DIR     = "logs"
DSGVO_DIR   = "compliance/dsgvo"

# Aufbewahrungsfristen (konfigurierbar via enterprise config)
DEFAULT_RETENTION = {
    "scan_history":      90,   # Tage — DSGVO: Datensparsamkeit
    "pdf_reports":       365,  # Tage — Sicherheitsprüfungsnachweise
    "auth_logs":         30,   # Tage — BSI-Empfehlung
    "gpt_analyses":      30,   # Tage
    "audit_log":         365,  # Tage — ISO 27001 A.12.4
    "incident_reports":  730,  # Tage — 2 Jahre (BSI DER.2)
}

VVT_PATH      = os.path.join(DSGVO_DIR, "vvt.json")          # Verarbeitungsverzeichnis
CONSENT_PATH  = os.path.join(DSGVO_DIR, "consents.json")     # Einwilligungen
DSFA_PATH     = os.path.join(DSGVO_DIR, "dsfa.json")         # Datenschutz-Folgenabschätzung


def _ensure_dirs():
    for d in [OUTPUT_DIR, HISTORY_DIR, LOG_DIR, DSGVO_DIR]:
        os.makedirs(d, exist_ok=True)


def _load_enterprise_config() -> Dict:
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("enterprise", {})
    except Exception:
        return {}


def _get_retention(data_type: str) -> int:
    cfg = _load_enterprise_config()
    retention = cfg.get("retention_days", {})
    return int(retention.get(data_type, DEFAULT_RETENTION.get(data_type, 90)))


# ── Art. 5 — Datenminimierung & Speicherbegrenzung ────────────────────────────

def apply_retention_policy(dry_run: bool = False) -> Dict[str, Any]:
    """
    Wendet Aufbewahrungsfristen an und löscht abgelaufene Dateien.
    DSGVO Art. 5 Abs. 1 lit. e — Speicherbegrenzung.
    Gibt Löschbericht zurück.
    """
    _ensure_dirs()
    report = {"deleted": [], "kept": [], "dry_run": dry_run}
    now    = datetime.now(timezone.utc)

    # Scan-History
    _apply_retention_dir(
        HISTORY_DIR, "*.json", "scan_history",
        now, report, dry_run
    )

    # PDF-Reports
    _apply_retention_dir(
        OUTPUT_DIR, "*.pdf", "pdf_reports",
        now, report, dry_run
    )
    _apply_retention_dir(
        OUTPUT_DIR, "*.pdf.enc", "pdf_reports",
        now, report, dry_run
    )
    _apply_retention_dir(
        OUTPUT_DIR, "*.txt", "pdf_reports",
        now, report, dry_run
    )

    # Auth-Logs
    _apply_retention_dir(
        LOG_DIR, "auth_attempts.json", "auth_logs",
        now, report, dry_run, single_file=True
    )

    # GPT-Analysen
    _apply_retention_dir(
        LOG_DIR, "gpt_analysis_*.txt", "gpt_analyses",
        now, report, dry_run
    )

    # Audit-Log (nur archivierte Rotationen löschen, nicht das aktive Log)
    _apply_retention_dir(
        LOG_DIR, "audit_*_*.jsonl", "audit_log",
        now, report, dry_run
    )

    # Auditierung der Löschung selbst
    try:
        from modules.audit_logger import log_data_deletion
        if report["deleted"]:
            log_data_deletion(
                f"{len(report['deleted'])} Dateien",
                user="dsgvo_retention",
                reason="retention_policy_enforcement"
            )
    except Exception:
        pass

    return report


def _apply_retention_dir(directory: str, pattern: str, data_type: str,
                          now: datetime, report: dict, dry_run: bool,
                          single_file: bool = False):
    retention_days = _get_retention(data_type)
    cutoff         = now - timedelta(days=retention_days)

    if single_file:
        path = os.path.join(directory, pattern)
        if os.path.exists(path):
            mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
            if mtime < cutoff:
                if not dry_run:
                    os.remove(path)
                report["deleted"].append({
                    "path": path, "age_days": (now - mtime).days,
                    "data_type": data_type
                })
        return

    for fpath in Path(directory).glob(pattern):
        mtime = datetime.fromtimestamp(fpath.stat().st_mtime, tz=timezone.utc)
        age_days = (now - mtime).days
        if mtime < cutoff:
            if not dry_run:
                fpath.unlink(missing_ok=True)
            report["deleted"].append({
                "path": str(fpath), "age_days": age_days,
                "data_type": data_type
            })
        else:
            report["kept"].append({
                "path": str(fpath), "age_days": age_days,
                "expires_in_days": retention_days - age_days,
            })


# ── Art. 17 — Recht auf Löschung ─────────────────────────────────────────────

def delete_data_for_target(target: str, requester: str = "user") -> Dict[str, Any]:
    """
    Löscht alle gespeicherten Daten für ein Scan-Target.
    DSGVO Art. 17 — Recht auf Löschung ('Recht auf Vergessenwerden').
    """
    deleted = []
    errors  = []

    # Scan-History
    for fpath in Path(HISTORY_DIR).glob(f"{target}_*.json"):
        try:
            fpath.unlink()
            deleted.append(str(fpath))
        except Exception as e:
            errors.append({"path": str(fpath), "error": str(e)})

    # Reports (die den Target-Namen enthalten)
    sanitized = target.replace("/", "_").replace(".", "_")
    for fpath in Path(OUTPUT_DIR).glob(f"*{sanitized}*"):
        try:
            fpath.unlink()
            deleted.append(str(fpath))
        except Exception as e:
            errors.append({"path": str(fpath), "error": str(e)})

    # Löschung auditieren
    try:
        from modules.audit_logger import log_data_deletion
        log_data_deletion(
            f"target:{target}",
            user=requester,
            reason="dsgvo_art17_erasure_request"
        )
    except Exception:
        pass

    return {
        "target":  target,
        "deleted": deleted,
        "errors":  errors,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "legal_basis": "DSGVO Art. 17 — Recht auf Löschung",
    }


def delete_all_personal_data(requester: str = "user") -> Dict[str, Any]:
    """
    Vollständige Datenlöschung (alle Scan-Daten, Logs, Reports).
    DSGVO Art. 17 Abs. 1.
    """
    deleted_count = 0
    errors        = []

    directories = [
        (HISTORY_DIR, "*.json"),
        (OUTPUT_DIR,  "*.pdf"),
        (OUTPUT_DIR,  "*.pdf.enc"),
        (OUTPUT_DIR,  "*.txt"),
        (OUTPUT_DIR,  "*.verification.json"),
        (LOG_DIR,     "gpt_analysis_*.txt"),
        (LOG_DIR,     "auth_attempts.json"),
    ]

    for directory, pattern in directories:
        for fpath in Path(directory).glob(pattern):
            try:
                fpath.unlink()
                deleted_count += 1
            except Exception as e:
                errors.append({"path": str(fpath), "error": str(e)})

    try:
        from modules.audit_logger import log
        from modules.audit_logger import AuditLevel, AuditCategory
        log(AuditLevel.AUDIT, AuditCategory.DATA, "full_data_erasure",
            {"deleted_count": deleted_count, "requester": requester,
             "legal_basis": "DSGVO Art. 17"},
            user=requester, result="success")
    except Exception:
        pass

    return {
        "deleted_count": deleted_count,
        "errors":        errors,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "legal_basis":   "DSGVO Art. 17 Abs. 1 — Vollständige Löschung",
    }


# ── Art. 20 — Datenportabilität ───────────────────────────────────────────────

def export_all_data(output_path: str, target: Optional[str] = None) -> Dict[str, Any]:
    """
    Exportiert alle gespeicherten Daten als strukturiertes JSON-Paket.
    DSGVO Art. 20 — Recht auf Datenübertragbarkeit.
    """
    _ensure_dirs()
    export = {
        "export_metadata": {
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "legal_basis":   "DSGVO Art. 20 — Datenportabilität",
            "format":        "JSON",
            "generated_by":  "GhostVenumAI Enterprise",
        },
        "scan_history": [],
        "reports":      [],
    }

    # Scan-History
    pattern = f"{target}_*.json" if target else "*.json"
    for fpath in sorted(Path(HISTORY_DIR).glob(pattern)):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                export["scan_history"].append(json.load(f))
        except Exception:
            pass

    # Report-Metadaten (keine verschlüsselten Binärdaten)
    for fpath in sorted(Path(OUTPUT_DIR).glob("*.txt")):
        export["reports"].append({
            "filename":  fpath.name,
            "size_bytes": fpath.stat().st_size,
            "modified":  datetime.fromtimestamp(fpath.stat().st_mtime, tz=timezone.utc).isoformat(),
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)

    try:
        from modules.audit_logger import log_data_export
        log_data_export("all_scan_data", user="system", format_="json")
    except Exception:
        pass

    return {
        "output_path": output_path,
        "scan_count":  len(export["scan_history"]),
        "report_count": len(export["reports"]),
        "legal_basis": "DSGVO Art. 20",
    }


# ── Art. 30 — Verarbeitungsverzeichnis (VVT) ──────────────────────────────────

def init_vvt() -> None:
    """Erstellt das Verarbeitungsverzeichnis gemäß DSGVO Art. 30."""
    _ensure_dirs()
    if os.path.exists(VVT_PATH):
        return

    vvt = {
        "version": "1.0",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "controller": {
            "name":    "Bitte eintragen",
            "address": "Bitte eintragen",
            "email":   "datenschutz@example.com",
        },
        "dpo": {
            "name":  "Datenschutzbeauftragter",
            "email": "dpo@example.com",
        },
        "processing_activities": [
            {
                "id":      "PA-001",
                "name":    "Netzwerk-Sicherheitsanalyse",
                "purpose": "Identifikation von Sicherheitslücken in autorisierten Netzwerken",
                "legal_basis": "Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) — Netzwerksicherheit",
                "data_categories": [
                    "IP-Adressen (intern)", "Portinformationen", "Dienst-Versionsdaten",
                    "Hostnamen (intern)", "MAC-Adressen (intern)",
                ],
                "data_subjects":   ["IT-Systeme (keine natürlichen Personen direkt betroffen)"],
                "recipients":      ["Intern: IT-Sicherheitsteam", "KI: Anthropic Claude API (anonymisiert)"],
                "third_countries": "Anthropic API (USA) — Standard-Vertragsklauseln (SCC), Art. 46 DSGVO",
                "retention_days":  90,
                "technical_measures": [
                    "AES-256-GCM Verschlüsselung für Reports",
                    "IP-Anonymisierung vor KI-API-Übertragung",
                    "PBKDF2-HMAC-SHA256 Authentifizierung",
                    "Manipulationssicheres Audit-Logging",
                ],
                "organizational_measures": [
                    "Zugriff nur für autorisiertes Personal",
                    "Nur auf eigenen/autorisierten Systemen",
                    "Dokumentierte Einwilligungen",
                ],
            },
            {
                "id":      "PA-002",
                "name":    "Audit-Protokollierung",
                "purpose": "Nachweisbarkeit von Sicherheitsereignissen (ISO 27001 A.12.4)",
                "legal_basis": "Art. 6 Abs. 1 lit. c DSGVO (rechtliche Verpflichtung) — ISO 27001",
                "data_categories": ["Benutzeraktionen", "Zeitstempel", "IP-Adressen", "Systemereignisse"],
                "data_subjects":   ["Systembenutzer"],
                "recipients":      ["Intern: CISO, Datenschutzbeauftragter"],
                "third_countries": "Keine",
                "retention_days":  365,
                "technical_measures": [
                    "HMAC-Kettenintegration (Manipulationsschutz)",
                    "Verschlüsselter Speicher",
                    "Log-Rotation",
                ],
            },
        ]
    }

    with open(VVT_PATH, "w", encoding="utf-8") as f:
        json.dump(vvt, f, indent=2, ensure_ascii=False)

    print(f"[DSGVO] Verarbeitungsverzeichnis erstellt: {VVT_PATH}")
    print("[DSGVO] Bitte Verantwortlichen und DSB-Daten eintragen!")


def get_vvt() -> Optional[Dict]:
    if os.path.exists(VVT_PATH):
        with open(VVT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ── Einwilligungsverwaltung ───────────────────────────────────────────────────

def record_consent(user: str, purpose: str, version: str = "1.0") -> str:
    """Speichert eine Einwilligung (DSGVO Art. 7)."""
    _ensure_dirs()
    consents = []
    if os.path.exists(CONSENT_PATH):
        try:
            with open(CONSENT_PATH, "r", encoding="utf-8") as f:
                consents = json.load(f)
        except Exception:
            pass

    consent_id = f"CONSENT-{int(time.time())}"
    consents.append({
        "id":        consent_id,
        "user":      user,
        "purpose":   purpose,
        "version":   version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    "active",
    })

    with open(CONSENT_PATH, "w", encoding="utf-8") as f:
        json.dump(consents, f, indent=2, ensure_ascii=False)

    return consent_id


def withdraw_consent(consent_id: str, user: str) -> bool:
    """Widerruft eine Einwilligung (DSGVO Art. 7 Abs. 3)."""
    if not os.path.exists(CONSENT_PATH):
        return False

    with open(CONSENT_PATH, "r", encoding="utf-8") as f:
        consents = json.load(f)

    found = False
    for c in consents:
        if c["id"] == consent_id and c["user"] == user:
            c["status"]    = "withdrawn"
            c["withdrawn_at"] = datetime.now(timezone.utc).isoformat()
            found = True

    if found:
        with open(CONSENT_PATH, "w", encoding="utf-8") as f:
            json.dump(consents, f, indent=2, ensure_ascii=False)

    return found


# ── DSGVO-Compliance-Status ───────────────────────────────────────────────────

def get_compliance_status() -> Dict[str, Any]:
    """Gibt den aktuellen DSGVO-Compliance-Status zurück."""
    cfg       = _load_enterprise_config()
    vvt       = get_vvt()
    retention = cfg.get("retention_days", DEFAULT_RETENTION)

    # Zähle Dateien
    scan_count   = len(list(Path(HISTORY_DIR).glob("*.json"))) if Path(HISTORY_DIR).exists() else 0
    report_count = len(list(Path(OUTPUT_DIR).glob("*.pdf")))   if Path(OUTPUT_DIR).exists()  else 0

    checks = {
        "vvt_exists":            vvt is not None,
        "retention_configured":  bool(retention),
        "vault_enabled":         cfg.get("vault_enabled", False),
        "audit_logging":         os.path.exists(os.path.join(LOG_DIR, "audit.jsonl")),
        "consent_tracking":      os.path.exists(CONSENT_PATH),
        "dsfa_completed":        os.path.exists(DSFA_PATH),
    }

    score  = sum(checks.values())
    total  = len(checks)

    return {
        "score":         f"{score}/{total}",
        "percentage":    round(score / total * 100),
        "checks":        checks,
        "scan_count":    scan_count,
        "report_count":  report_count,
        "retention":     retention,
        "vvt_updated":   vvt.get("last_updated") if vvt else None,
        "articles": {
            "Art.5":  "Grundsätze — Datensparsamkeit, Speicherbegrenzung",
            "Art.17": "Recht auf Löschung — implementiert",
            "Art.20": "Datenportabilität — implementiert",
            "Art.30": "Verarbeitungsverzeichnis — " + ("vorhanden" if vvt else "FEHLT"),
            "Art.32": "Technische Maßnahmen — AES-256-GCM, PBKDF2, HMAC-Audit",
            "Art.33": "Meldepflicht — via Incident Manager",
        }
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        print(json.dumps(get_compliance_status(), indent=2, ensure_ascii=False))

    elif cmd == "retention":
        dry = "--dry-run" in sys.argv
        report = apply_retention_policy(dry_run=dry)
        print(f"[{'DRY RUN' if dry else 'EXECUTED'}] "
              f"Gelöscht: {len(report['deleted'])} | "
              f"Behalten: {len(report['kept'])}")
        for d in report["deleted"]:
            print(f"  ❌ {d['path']} ({d['age_days']} Tage alt)")

    elif cmd == "init-vvt":
        init_vvt()

    elif cmd == "export":
        path = sys.argv[2] if len(sys.argv) > 2 else "dsgvo_export.json"
        result = export_all_data(path)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == "delete-target":
        if len(sys.argv) < 3:
            print("Usage: dsgvo.py delete-target <target>")
            sys.exit(1)
        result = delete_data_for_target(sys.argv[2])
        print(json.dumps(result, indent=2, ensure_ascii=False))

    else:
        print("Befehle: status | retention [--dry-run] | init-vvt | export [path] | delete-target <target>")
