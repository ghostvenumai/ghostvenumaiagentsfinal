# modules/incident_manager.py — GhostVenumAI Enterprise
# Sicherheitsvorfallverwaltung & DSGVO-Meldepflicht-Timer
# ISO 27001 A.16 (Informationssicherheitsvorfälle)
# BSI DER.2 (Security Incident Management)
# DSGVO Art. 33 (72h Meldepflicht an Aufsichtsbehörde)
# DSGVO Art. 34 (Benachrichtigung Betroffener)

import os
import json
import time
import threading
import hashlib
import smtplib
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any
from enum import Enum

INCIDENT_DIR  = "compliance/incidents"
INCIDENT_LOG  = os.path.join(INCIDENT_DIR, "incidents.json")
NOTIF_LOG     = os.path.join(INCIDENT_DIR, "notifications.json")

DSGVO_NOTIFY_HOURS = 72   # Art. 33 — Meldepflicht innerhalb 72 Stunden


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class IncidentType(str, Enum):
    DATA_BREACH       = "data_breach"           # Datenpanne — Art. 33 DSGVO!
    UNAUTHORIZED_ACCESS = "unauthorized_access" # Unberechtigter Zugriff
    AUTH_FAILURE      = "auth_failure"          # Brute-Force / Auth-Fehler
    TAMPERING         = "tampering"             # Log-Manipulation erkannt
    CONFIG_CHANGE     = "config_change"         # Unerwartete Konfigurationsänderung
    SCAN_ANOMALY      = "scan_anomaly"          # Ungewöhnliche Netzwerkänderung
    API_ABUSE         = "api_abuse"             # API-Missbrauch / Rate-Limit
    SYSTEM_COMPROMISE = "system_compromise"     # Systemkompromittierung
    POLICY_VIOLATION  = "policy_violation"      # Richtlinienverletzung


_timer_lock  = threading.Lock()
_dsgvo_timers: Dict[str, threading.Timer] = {}


def _ensure_dirs():
    os.makedirs(INCIDENT_DIR, exist_ok=True)


# ── Incident CRUD ─────────────────────────────────────────────────────────────

def _load_incidents() -> List[Dict[str, Any]]:
    _ensure_dirs()
    if not os.path.exists(INCIDENT_LOG):
        return []
    try:
        with open(INCIDENT_LOG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_incidents(incidents: List[Dict[str, Any]]) -> None:
    tmp = INCIDENT_LOG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)
    os.replace(tmp, INCIDENT_LOG)


def create_incident(
    incident_type: IncidentType,
    severity:      Severity,
    title:         str,
    description:   str,
    affected_data: Optional[str] = None,
    reported_by:   str = "system",
    source_ip:     str = "127.0.0.1",
) -> str:
    """
    Erstellt einen neuen Sicherheitsvorfall.
    Startet automatisch den DSGVO-72h-Timer bei Datenpannen.
    """
    incidents  = _load_incidents()
    now        = datetime.now(timezone.utc)
    incident_id = f"INC-{now.strftime('%Y%m%d')}-{len(incidents)+1:04d}"

    dsgvo_required = incident_type == IncidentType.DATA_BREACH
    deadline_72h   = (now + timedelta(hours=72)).isoformat() if dsgvo_required else None

    incident = {
        "id":              incident_id,
        "type":            incident_type.value,
        "severity":        severity.value,
        "title":           title,
        "description":     description,
        "affected_data":   affected_data,
        "reported_by":     reported_by,
        "source_ip":       source_ip,
        "status":          "open",
        "created_at":      now.isoformat(),
        "updated_at":      now.isoformat(),
        "resolved_at":     None,
        "resolution":      None,
        "dsgvo_art33":     dsgvo_required,
        "dsgvo_deadline":  deadline_72h,
        "dsgvo_notified":  False,
        "notifications":   [],
        "timeline":        [
            {
                "ts":     now.isoformat(),
                "action": "Vorfall erstellt",
                "by":     reported_by,
            }
        ],
    }

    incidents.append(incident)
    _save_incidents(incidents)

    # Audit-Log
    try:
        from modules.audit_logger import log_incident
        log_incident(
            severity.value,
            title,
            {"incident_id": incident_id, "type": incident_type.value,
             "dsgvo_art33": dsgvo_required}
        )
    except Exception:
        pass

    # DSGVO 72h Timer starten (bei Datenpannen)
    if dsgvo_required:
        _start_dsgvo_timer(incident_id, deadline_72h)

    # Sofort-Benachrichtigung bei High/Critical
    if severity in (Severity.HIGH, Severity.CRITICAL):
        _send_notifications(incident_id, severity, title,
                            "SOFORT-MELDUNG: Kritischer Sicherheitsvorfall erkannt!")

    return incident_id


def update_incident(incident_id: str, updates: Dict[str, Any],
                    updated_by: str = "system") -> bool:
    incidents = _load_incidents()
    for i, inc in enumerate(incidents):
        if inc["id"] == incident_id:
            now = datetime.now(timezone.utc).isoformat()
            for k, v in updates.items():
                if k not in ("id", "created_at"):
                    incidents[i][k] = v
            incidents[i]["updated_at"] = now
            incidents[i]["timeline"].append({
                "ts":     now,
                "action": f"Aktualisierung: {list(updates.keys())}",
                "by":     updated_by,
            })
            _save_incidents(incidents)
            return True
    return False


def resolve_incident(incident_id: str, resolution: str,
                     resolved_by: str = "system") -> bool:
    now = datetime.now(timezone.utc).isoformat()
    success = update_incident(incident_id, {
        "status":      "resolved",
        "resolved_at": now,
        "resolution":  resolution,
    }, resolved_by)

    if success:
        _cancel_dsgvo_timer(incident_id)
        try:
            from modules.audit_logger import log
            from modules.audit_logger import AuditLevel, AuditCategory
            log(AuditLevel.AUDIT, AuditCategory.INCIDENT,
                "incident_resolved",
                {"incident_id": incident_id, "resolution": resolution},
                user=resolved_by, result="success")
        except Exception:
            pass

    return success


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    for inc in _load_incidents():
        if inc["id"] == incident_id:
            return inc
    return None


def list_incidents(status_filter: Optional[str] = None,
                   severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    incidents = _load_incidents()
    if status_filter:
        incidents = [i for i in incidents if i.get("status") == status_filter]
    if severity_filter:
        incidents = [i for i in incidents if i.get("severity") == severity_filter]
    return sorted(incidents, key=lambda x: x["created_at"], reverse=True)


# ── DSGVO 72h Meldepflicht-Timer ─────────────────────────────────────────────

def _start_dsgvo_timer(incident_id: str, deadline_iso: str) -> None:
    """Startet einen Timer für die DSGVO Art. 33 Meldepflicht (72h)."""
    deadline = datetime.fromisoformat(deadline_iso)
    now      = datetime.now(timezone.utc)
    remaining = (deadline - now).total_seconds()

    if remaining <= 0:
        _dsgvo_deadline_exceeded(incident_id)
        return

    with _timer_lock:
        if incident_id in _dsgvo_timers:
            _dsgvo_timers[incident_id].cancel()

        timer = threading.Timer(remaining, _dsgvo_deadline_exceeded, args=[incident_id])
        timer.daemon = True
        timer.start()
        _dsgvo_timers[incident_id] = timer

    print(f"[IncidentManager] ⚠️  DSGVO Art.33 Timer gestartet für {incident_id}")
    print(f"[IncidentManager] Meldepflicht-Frist: {deadline_iso}")
    print(f"[IncidentManager] Verbleibende Zeit: {remaining/3600:.1f} Stunden")


def _cancel_dsgvo_timer(incident_id: str) -> None:
    with _timer_lock:
        timer = _dsgvo_timers.pop(incident_id, None)
        if timer:
            timer.cancel()


def _dsgvo_deadline_exceeded(incident_id: str) -> None:
    """Wird aufgerufen wenn 72h-Frist überschritten."""
    incident = get_incident(incident_id)
    if not incident:
        return

    if incident.get("dsgvo_notified"):
        return

    msg = (
        f"⛔ DSGVO Art. 33 — 72h-Meldefrist ÜBERSCHRITTEN!\n"
        f"Vorfall: {incident_id}\n"
        f"Titel: {incident.get('title')}\n"
        f"Erstellt: {incident.get('created_at')}\n"
        f"SOFORTIGE Meldung an Aufsichtsbehörde (BSI/LDA) erforderlich!"
    )

    print(f"\n{'!'*60}")
    print(msg)
    print(f"{'!'*60}\n")

    try:
        from modules.audit_logger import log
        from modules.audit_logger import AuditLevel, AuditCategory
        log(AuditLevel.CRITICAL, AuditCategory.INCIDENT,
            "dsgvo_art33_deadline_exceeded",
            {"incident_id": incident_id, "title": incident.get("title"),
             "deadline": incident.get("dsgvo_deadline")},
            user="system", result="deadline_exceeded")
    except Exception:
        pass

    _send_notifications(incident_id, Severity.CRITICAL,
                        incident.get("title", "?"),
                        "DSGVO Art.33 — 72h-MELDEFRIST ÜBERSCHRITTEN!")

    update_incident(incident_id, {"dsgvo_notified": True, "status": "escalated"})


# ── Benachrichtigungen ────────────────────────────────────────────────────────

def _load_notif_config() -> Dict[str, Any]:
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("enterprise", {}).get("notifications", {})
    except Exception:
        return {}


def _send_notifications(incident_id: str, severity: Severity,
                         title: str, message: str) -> None:
    """Sendet Benachrichtigungen via konfigurierten Kanälen."""
    cfg     = _load_notif_config()
    sent    = []

    # Webhook (Slack, Teams, etc.)
    webhook = cfg.get("webhook_url")
    if webhook:
        try:
            payload = json.dumps({
                "text":        f"🚨 GhostVenumAI Sicherheitsvorfall\n{message}",
                "incident_id": incident_id,
                "severity":    severity.value,
                "title":       title,
            }).encode("utf-8")
            req = urllib.request.Request(
                webhook, data=payload,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=10)
            sent.append("webhook")
        except Exception as e:
            print(f"[IncidentManager] Webhook-Fehler: {e}")

    # E-Mail (SMTP)
    smtp_cfg = cfg.get("smtp", {})
    if smtp_cfg.get("host") and smtp_cfg.get("to"):
        try:
            _send_email(
                smtp_cfg,
                subject=f"[GhostVenum] {severity.value.upper()}: {title}",
                body=f"Vorfall-ID: {incident_id}\n\n{message}\n\nBitte umgehend prüfen.",
            )
            sent.append("email")
        except Exception as e:
            print(f"[IncidentManager] E-Mail-Fehler: {e}")

    # Benachrichtigung loggen
    _ensure_dirs()
    notifs = []
    if os.path.exists(NOTIF_LOG):
        try:
            with open(NOTIF_LOG, "r", encoding="utf-8") as f:
                notifs = json.load(f)
        except Exception:
            pass

    notifs.append({
        "incident_id": incident_id,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "channels":    sent,
        "message":     message,
    })

    with open(NOTIF_LOG, "w", encoding="utf-8") as f:
        json.dump(notifs, f, indent=2, ensure_ascii=False)


def _send_email(cfg: Dict, subject: str, body: str) -> None:
    host     = cfg["host"]
    port     = int(cfg.get("port", 587))
    user     = cfg.get("user", "")
    password = cfg.get("password", "")
    to       = cfg["to"]
    sender   = cfg.get("from", user)

    msg = (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body}"
    ).encode("utf-8")

    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.sendmail(sender, [to], msg)


# ── Automatische Vorfall-Erkennung ────────────────────────────────────────────

def check_auth_anomalies(failed_attempts: int, source_ip: str = "127.0.0.1") -> Optional[str]:
    """Erstellt Vorfall bei zu vielen Authentifizierungsfehlern."""
    threshold = 5
    if failed_attempts >= threshold:
        return create_incident(
            IncidentType.AUTH_FAILURE,
            Severity.HIGH if failed_attempts >= 10 else Severity.MEDIUM,
            f"Brute-Force-Angriff erkannt ({failed_attempts} Fehlversuche)",
            f"Von IP {source_ip} wurden {failed_attempts} fehlgeschlagene "
            f"Anmeldeversuche innerhalb kurzer Zeit registriert.",
            reported_by="auto_detection",
            source_ip=source_ip,
        )
    return None


def check_audit_tampering() -> Optional[str]:
    """Erstellt Vorfall wenn Audit-Log-Manipulation erkannt wird."""
    try:
        from modules.audit_logger import verify_chain
        result = verify_chain()
        if not result["valid"]:
            return create_incident(
                IncidentType.TAMPERING,
                Severity.CRITICAL,
                "Audit-Log-Manipulation erkannt!",
                f"HMAC-Kettenverifikation fehlgeschlagen. "
                f"{len(result['errors'])} fehlerhafte Einträge:\n"
                + json.dumps(result["errors"], indent=2),
                affected_data="Audit-Log (logs/audit.jsonl)",
                reported_by="integrity_check",
            )
    except Exception:
        pass
    return None


def check_scan_anomalies(target: str, new_ports: List, closed_ports: List) -> Optional[str]:
    """Erstellt Vorfall bei signifikanten Netzwerkänderungen."""
    total_changes = len(new_ports) + len(closed_ports)
    if total_changes >= 5:
        return create_incident(
            IncidentType.SCAN_ANOMALY,
            Severity.MEDIUM,
            f"Signifikante Netzwerkänderung bei {target}",
            f"Erkannt: {len(new_ports)} neue Ports, {len(closed_ports)} geschlossene Ports.\n"
            f"Neue Ports: {new_ports}\nGeschlossene Ports: {closed_ports}",
            reported_by="monitor_engine",
        )
    return None


# ── Compliance-Bericht ────────────────────────────────────────────────────────

def get_incident_summary() -> Dict[str, Any]:
    incidents = _load_incidents()
    now       = datetime.now(timezone.utc)

    open_count     = sum(1 for i in incidents if i["status"] == "open")
    critical_count = sum(1 for i in incidents if i["severity"] == "critical")
    dsgvo_open     = [i for i in incidents
                      if i.get("dsgvo_art33") and i["status"] == "open"]

    # Überprüfe überfällige DSGVO-Meldungen
    overdue_dsgvo = []
    for inc in dsgvo_open:
        deadline = datetime.fromisoformat(inc["dsgvo_deadline"])
        if deadline < now and not inc.get("dsgvo_notified"):
            hours_overdue = (now - deadline).total_seconds() / 3600
            overdue_dsgvo.append({
                "id":           inc["id"],
                "title":        inc["title"],
                "hours_overdue": round(hours_overdue, 1),
            })

    return {
        "total":           len(incidents),
        "open":            open_count,
        "resolved":        sum(1 for i in incidents if i["status"] == "resolved"),
        "critical":        critical_count,
        "dsgvo_pending":   len(dsgvo_open),
        "dsgvo_overdue":   overdue_dsgvo,
        "last_incident":   incidents[-1]["created_at"] if incidents else None,
        "iso27001_ref":    "ISO 27001 A.16 — Information Security Incident Management",
        "bsi_ref":         "BSI DER.2 — Security Incident Management",
        "dsgvo_ref":       "DSGVO Art. 33/34 — Meldepflicht bei Datenpannen",
    }


# ── BSI-Meldebogen (Vorlage) ───────────────────────────────────────────────────

def generate_bsi_report(incident_id: str) -> Dict[str, Any]:
    """
    Generiert einen BSI-konformen Meldebogen für kritische Vorfälle.
    Ref: BSI KRITIS-Meldepflicht, § 8b BSIG
    """
    inc = get_incident(incident_id)
    if not inc:
        return {"error": "Vorfall nicht gefunden"}

    return {
        "meldebogen": "BSI-Meldebogen Sicherheitsvorfall",
        "version":    "1.0",
        "erstellt":   datetime.now(timezone.utc).isoformat(),
        "vorfall": {
            "id":           inc["id"],
            "titel":        inc["title"],
            "beschreibung": inc["description"],
            "schwere":      inc["severity"],
            "typ":          inc["type"],
            "erkannt_am":   inc["created_at"],
            "gemeldet_von": inc["reported_by"],
        },
        "betroffene_systeme": {
            "system":    "GhostVenumAI Enterprise",
            "funktion":  "Netzwerk-Sicherheitsanalyse",
            "daten":     inc.get("affected_data", "Wird analysiert"),
        },
        "massnahmen": {
            "sofortmassnahmen":  inc.get("resolution", "Ausstehend"),
            "status":            inc["status"],
        },
        "dsgvo": {
            "art33_relevant":  inc.get("dsgvo_art33", False),
            "frist":           inc.get("dsgvo_deadline"),
            "gemeldet":        inc.get("dsgvo_notified", False),
        },
        "hinweis": "Bitte an BSI-CERT melden: cert@bsi.bund.de | +49 228 9582-888",
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else "summary"

    if cmd == "summary":
        print(json.dumps(get_incident_summary(), indent=2, ensure_ascii=False))

    elif cmd == "list":
        for inc in list_incidents():
            status_icon = "🔴" if inc["status"] == "open" else "✅"
            dsgvo_icon  = " ⚠️DSGVO" if inc.get("dsgvo_art33") and inc["status"] == "open" else ""
            print(f"{status_icon} [{inc['id']}] [{inc['severity'].upper():8}] "
                  f"{inc['title']}{dsgvo_icon}")

    elif cmd == "create":
        incident_id = create_incident(
            IncidentType.POLICY_VIOLATION,
            Severity.MEDIUM,
            sys.argv[2] if len(sys.argv) > 2 else "Test-Vorfall",
            "Manuell erstellter Test-Vorfall",
            reported_by="cli",
        )
        print(f"✅ Vorfall erstellt: {incident_id}")

    elif cmd == "bsi-report":
        if len(sys.argv) < 3:
            print("Usage: incident_manager.py bsi-report <INCIDENT-ID>")
            sys.exit(1)
        report = generate_bsi_report(sys.argv[2])
        print(json.dumps(report, indent=2, ensure_ascii=False))

    elif cmd == "check-integrity":
        result = check_audit_tampering()
        if result:
            print(f"⚠️  Manipulationsvorfall erstellt: {result}")
        else:
            print("✅ Audit-Log-Integrität OK.")

    else:
        print("Befehle: summary | list | create [titel] | bsi-report <ID> | check-integrity")
