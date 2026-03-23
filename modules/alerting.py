# modules/alerting.py — GhostVenumAI Enterprise
# E-Mail-Alerts bei kritischen Scan-Befunden
# ISO 27001 A.16.1 | BSI DER.2.1

import os
import json
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Optional

# Kritische Ports die immer alarmieren
CRITICAL_PORTS = {
    21:   "FTP (unverschlüsselt)",
    23:   "Telnet (unverschlüsselt)",
    25:   "SMTP (Open Relay Risiko)",
    135:  "RPC (Windows-Angriffsfläche)",
    139:  "NetBIOS",
    445:  "SMB (EternalBlue-Risiko)",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL (öffentlich erreichbar)",
    3389: "RDP (Brute-Force Ziel)",
    4444: "Metasploit Default",
    5900: "VNC (unverschlüsselt)",
    6379: "Redis (ungeschützt)",
    27017:"MongoDB (ungeschützt)",
}

# CVE-Keywords die kritisch sind
CRITICAL_CVE_PATTERN = re.compile(
    r'(CVE-\d{4}-\d+|critical|exploit|remote code|rce|buffer overflow|'
    r'authentication bypass|sql injection|command injection)',
    re.IGNORECASE
)


def _load_smtp_config() -> dict:
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("enterprise", {}).get("notifications", {}).get("smtp", {})
    except Exception:
        return {}


def _smtp_configured(smtp: dict) -> bool:
    return bool(smtp.get("host") and smtp.get("user") and smtp.get("to"))


def send_alert_email(subject: str, body: str, severity: str = "HIGH") -> bool:
    """Sendet eine Alert-E-Mail via SMTP. Gibt True bei Erfolg zurück."""
    smtp = _load_smtp_config()
    if not _smtp_configured(smtp):
        _log_alert_skipped(subject, "SMTP nicht konfiguriert")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[GhostVenumAI] [{severity}] {subject}"
        msg["From"]    = smtp.get("from") or smtp["user"]
        msg["To"]      = smtp["to"]
        msg["X-Priority"] = "1" if severity == "CRITICAL" else "2"

        # Plain Text
        text_part = MIMEText(body, "plain", "utf-8")

        # HTML-Version
        html_body = _build_html_alert(subject, body, severity)
        html_part = MIMEText(html_body, "html", "utf-8")

        msg.attach(text_part)
        msg.attach(html_part)

        host = smtp["host"]
        port = int(smtp.get("port", 587))

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp["user"], smtp["password"])
            server.sendmail(msg["From"], smtp["to"], msg.as_string())

        _audit_alert(subject, severity, "sent", smtp["to"])
        return True

    except Exception as e:
        _audit_alert(subject, severity, f"failed: {e}", smtp.get("to", "?"))
        return False


def analyze_scan_for_alerts(scan_output: str, target: str) -> Optional[dict]:
    """
    Analysiert Scan-Output auf kritische Befunde.
    Gibt Alert-Dict zurück oder None wenn kein Alert nötig.
    """
    findings = []
    severity = "INFO"

    lines = scan_output.lower()

    # Kritische Ports prüfen
    for port, description in CRITICAL_PORTS.items():
        pattern = rf'\b{port}/tcp\s+open\b'
        if re.search(pattern, scan_output, re.IGNORECASE):
            findings.append(f"KRITISCHER PORT OFFEN: {port}/tcp — {description}")
            severity = "CRITICAL"

    # CVE / Exploit-Erwähnungen
    cve_matches = CRITICAL_CVE_PATTERN.findall(scan_output)
    if cve_matches:
        unique = list(dict.fromkeys(cve_matches))[:10]
        findings.append(f"SCHWACHSTELLEN GEFUNDEN: {', '.join(unique)}")
        if severity != "CRITICAL":
            severity = "HIGH"

    # Anonym-Zugriff
    if any(kw in lines for kw in ["anonymous ftp", "anonymous login", "no authentication"]):
        findings.append("ANONYMER ZUGRIFF MÖGLICH (FTP/Service ohne Auth)")
        severity = "CRITICAL"

    # Default-Credentials
    if any(kw in lines for kw in ["default credentials", "default password", "admin:admin"]):
        findings.append("STANDARD-PASSWÖRTER ERKANNT")
        severity = "CRITICAL"

    if not findings:
        return None

    return {
        "target":   target,
        "severity": severity,
        "findings": findings,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count":    len(findings),
    }


def send_scan_alert(scan_output: str, target: str) -> bool:
    """Kompletter Alert-Flow: Analyse + Versand."""
    alert = analyze_scan_for_alerts(scan_output, target)
    if not alert:
        return False

    subject = f"Scan-Alarm: {alert['count']} kritische Befunde bei {target}"

    body = f"""GhostVenumAI Security Alert
{'=' * 50}
Zeitpunkt : {alert['timestamp']}
Ziel      : {target}
Schwere   : {alert['severity']}
Befunde   : {alert['count']}

KRITISCHE BEFUNDE:
{chr(10).join(f'  • {f}' for f in alert['findings'])}

{'=' * 50}
Bitte sofortige Überprüfung empfohlen.
GhostVenumAI Enterprise — Automatischer Alert
"""

    return send_alert_email(subject, body, alert["severity"])


def _build_html_alert(subject: str, body: str, severity: str) -> str:
    color = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22",
             "MEDIUM": "#f39c12", "INFO": "#3498db"}.get(severity, "#95a5a6")

    findings_html = ""
    for line in body.split("\n"):
        if line.startswith("  •"):
            findings_html += f'<li style="color:#c0392b;font-weight:bold">{line[3:].strip()}</li>'

    return f"""<!DOCTYPE html>
<html><body style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px">
<div style="max-width:600px;margin:auto;background:#16213e;border-radius:8px;padding:20px;border-left:5px solid {color}">
  <h2 style="color:{color};margin-top:0">&#9888; GhostVenumAI Security Alert</h2>
  <p><strong>Schweregrad:</strong> <span style="color:{color}">{severity}</span></p>
  <p><strong>Betreff:</strong> {subject}</p>
  <hr style="border-color:#333">
  <h3 style="color:#f39c12">Kritische Befunde:</h3>
  <ul style="line-height:1.8">{findings_html}</ul>
  <hr style="border-color:#333">
  <p style="color:#666;font-size:12px">GhostVenumAI Enterprise — Automatischer Sicherheitsalert</p>
</div>
</body></html>"""


def _log_alert_skipped(subject: str, reason: str):
    try:
        from modules.audit_logger import log
        from modules.audit_logger import AuditLevel, AuditCategory
        log(AuditLevel.WARN, AuditCategory.SYSTEM, "alert_skipped",
            details={"subject": subject, "reason": reason})
    except Exception:
        pass


def _audit_alert(subject: str, severity: str, result: str, recipient: str):
    try:
        from modules.audit_logger import log
        from modules.audit_logger import AuditLevel, AuditCategory
        log(AuditLevel.AUDIT, AuditCategory.INCIDENT, "email_alert",
            result=result,
            details={"subject": subject, "severity": severity, "to": recipient})
    except Exception:
        pass


def smtp_test() -> dict:
    """Testet die SMTP-Konfiguration mit einer Test-Mail."""
    smtp = _load_smtp_config()
    if not _smtp_configured(smtp):
        return {"ok": False, "error": "SMTP nicht konfiguriert (host/user/to fehlt)"}

    ok = send_alert_email(
        "SMTP-Test erfolgreich",
        "Dies ist eine Test-E-Mail von GhostVenumAI Enterprise.\n"
        "SMTP-Konfiguration ist korrekt.",
        severity="INFO"
    )
    return {"ok": ok, "to": smtp.get("to")}
