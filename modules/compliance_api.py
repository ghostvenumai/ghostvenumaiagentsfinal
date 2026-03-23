# modules/compliance_api.py — GhostVenumAI Enterprise
# Flask Blueprint: Compliance-API-Endpunkte
# Registrierung in app.py: app.register_blueprint(compliance_bp)

import os
import json
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request

compliance_bp = Blueprint("compliance", __name__, url_prefix="/api/compliance")


# ── Gesamt-Status ─────────────────────────────────────────────────────────────

@compliance_bp.route("/status")
def compliance_status():
    """Kombinierter Compliance-Status für das Dashboard-Overview."""
    result = {}

    # DSGVO
    try:
        from modules.dsgvo import get_compliance_status
        result["dsgvo"] = get_compliance_status()
    except Exception as e:
        result["dsgvo"] = {"error": str(e)}

    # ISO 27001
    try:
        result["iso27001"] = _get_iso27001_status()
    except Exception as e:
        result["iso27001"] = {"error": str(e)}

    # BSI
    try:
        result["bsi"] = _get_bsi_status()
    except Exception as e:
        result["bsi"] = {"error": str(e)}

    # Vorfälle
    try:
        from modules.incident_manager import get_incident_summary
        result["incidents"] = get_incident_summary()
    except Exception as e:
        result["incidents"] = {"error": str(e)}

    # Vault-Status
    try:
        from modules.key_manager import vault_status
        result["vault"] = vault_status()
    except Exception as e:
        result["vault"] = {"error": str(e)}

    # Audit aktiv?
    result["audit_active"] = os.path.exists("logs/audit.jsonl")

    return jsonify(result)


# ── ISO 27001 ─────────────────────────────────────────────────────────────────

@compliance_bp.route("/iso27001")
def iso27001_status():
    return jsonify(_get_iso27001_status())


def _get_iso27001_status():
    """Bewertet die ISO 27001:2022 Kontrollen."""
    vault_ok  = os.path.exists("config.vault")
    audit_ok  = os.path.exists("logs/audit.jsonl")
    users_ok  = os.path.exists("config.users.json")
    vvt_ok    = os.path.exists("compliance/dsgvo/vvt.json")
    inc_ok    = os.path.exists("compliance/incidents/incidents.json")

    controls = {
        "A.5 — Organisatorische Maßnahmen": [
            {"id": "A.5.1",  "name": "Informationssicherheitsrichtlinien",
             "implemented": vvt_ok, "partial": False,
             "description": "Richtlinien für Informationssicherheit"},
            {"id": "A.5.31", "name": "Rechtliche/regulatorische Anforderungen",
             "implemented": True, "partial": False,
             "description": "DSGVO, BSI BSIG, ISO 27001 berücksichtigt"},
        ],
        "A.8 — Technologische Maßnahmen": [
            {"id": "A.8.2",  "name": "Berechtigungskonzept (RBAC)",
             "implemented": users_ok, "partial": not users_ok,
             "description": "Rollenbasierte Zugangssteuerung implementiert"},
            {"id": "A.8.5",  "name": "Sichere Authentifizierung",
             "implemented": users_ok, "partial": False,
             "description": "PBKDF2-HMAC-SHA256 (600.000 Iter.), TOTP-MFA verfügbar"},
            {"id": "A.8.7",  "name": "Schutz vor Schadsoftware",
             "implemented": True, "partial": False,
             "description": "Defensive Architektur, keine Exploit-Generierung"},
            {"id": "A.8.15", "name": "Protokollierung (Audit-Log)",
             "implemented": audit_ok, "partial": False,
             "description": "HMAC-gesicherte Audit-Protokolle mit Kettenintegrität"},
            {"id": "A.8.16", "name": "Überwachung (Monitoring)",
             "implemented": True, "partial": False,
             "description": "24/7 Netzwerk-Monitoring mit Anomalie-Erkennung"},
            {"id": "A.8.24", "name": "Kryptographie",
             "implemented": vault_ok, "partial": not vault_ok,
             "description": "AES-256-GCM Verschlüsselung, PBKDF2, verschlüsselter Key-Vault"},
        ],
        "A.9 — Zugangskontrolle": [
            {"id": "A.9.1",  "name": "Zugangskontrollrichtlinie",
             "implemented": users_ok, "partial": False,
             "description": "RBAC mit Rollen: admin, analyst, viewer, auditor"},
            {"id": "A.9.2",  "name": "Benutzerzugangsverwaltung",
             "implemented": users_ok, "partial": False,
             "description": "Zentrale Benutzerverwaltung mit Audit-Trail"},
            {"id": "A.9.4",  "name": "Sichere Anmeldeverfahren",
             "implemented": True, "partial": False,
             "description": "TOTP-MFA, Session-Management, Anti-Brute-Force"},
        ],
        "A.10 — Kryptographie": [
            {"id": "A.10.1", "name": "Kryptographische Maßnahmen",
             "implemented": vault_ok, "partial": not vault_ok,
             "description": "Verschlüsselter Vault (AES-256-GCM), Report-Verschlüsselung"},
        ],
        "A.12 — Betriebssicherheit": [
            {"id": "A.12.4", "name": "Protokollierung und Überwachung",
             "implemented": audit_ok, "partial": False,
             "description": "Tamper-proof HMAC-Audit-Log, Log-Rotation, Verifikation"},
        ],
        "A.16 — Vorfallsmanagement": [
            {"id": "A.16.1", "name": "Behandlung von Sicherheitsvorfällen",
             "implemented": inc_ok, "partial": not inc_ok,
             "description": "Incident Manager mit DSGVO Art.33 Timer und BSI-Meldebogen"},
        ],
        "A.17 — Business Continuity": [
            {"id": "A.17.1", "name": "Datensicherung",
             "implemented": False, "partial": True,
             "description": "Lokale Scan-History. Empfehlung: externe Backup-Lösung konfigurieren"},
        ],
        "A.18 — Compliance": [
            {"id": "A.18.1", "name": "Einhaltung gesetzlicher Anforderungen",
             "implemented": vvt_ok, "partial": not vvt_ok,
             "description": "DSGVO-Konformität, VVT (Art. 30), Datenlöschung (Art. 17)"},
        ],
    }

    total      = sum(len(v) for v in controls.values())
    implemented = sum(c["implemented"] for v in controls.values() for c in v)
    partial     = sum(c["partial"]     for v in controls.values() for c in v)
    pct         = round((implemented + partial * 0.5) / total * 100)

    return {
        "score":      f"{implemented}/{total}",
        "percentage": pct,
        "controls":   controls,
        "standard":   "ISO/IEC 27001:2022",
    }


# ── DSGVO ─────────────────────────────────────────────────────────────────────

@compliance_bp.route("/dsgvo")
def dsgvo_status():
    from modules.dsgvo import get_compliance_status
    return jsonify(get_compliance_status())


@compliance_bp.route("/dsgvo/export", methods=["POST"])
def dsgvo_export():
    from modules.dsgvo import export_all_data
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = f"output/dsgvo_export_{ts}.json"
    os.makedirs("output", exist_ok=True)
    result = export_all_data(path)
    return jsonify(result)


@compliance_bp.route("/dsgvo/init-vvt", methods=["POST"])
def dsgvo_init_vvt():
    from modules.dsgvo import init_vvt
    init_vvt()
    return jsonify({"ok": True, "message": "VVT initialisiert."})


@compliance_bp.route("/dsgvo/retention", methods=["POST"])
def dsgvo_retention():
    from modules.dsgvo import apply_retention_policy
    data    = request.get_json(force=True) or {}
    dry_run = data.get("dry_run", False)
    report  = apply_retention_policy(dry_run=dry_run)
    return jsonify({
        "deleted": len(report["deleted"]),
        "kept":    len(report["kept"]),
        "details": report,
    })


@compliance_bp.route("/dsgvo/delete-all", methods=["POST"])
def dsgvo_delete_all():
    from modules.dsgvo import delete_all_personal_data
    result = delete_all_personal_data(requester="web_api")
    return jsonify(result)


@compliance_bp.route("/dsgvo/delete-target/<target>", methods=["DELETE"])
def dsgvo_delete_target(target):
    from modules.dsgvo import delete_data_for_target
    result = delete_data_for_target(target, requester="web_api")
    return jsonify(result)


# ── BSI ────────────────────────────────────────────────────────────────────────

@compliance_bp.route("/bsi")
def bsi_status():
    return jsonify(_get_bsi_status())


def _get_bsi_status():
    """BSI IT-Grundschutz Bausteine."""
    vault_ok  = os.path.exists("config.vault")
    audit_ok  = os.path.exists("logs/audit.jsonl")
    users_ok  = os.path.exists("config.users.json")
    inc_ok    = os.path.exists("compliance/incidents/incidents.json")

    bausteine = [
        {"id": "APP.3.1", "name": "Web-Anwendungen",
         "implemented": True,
         "status": "Implementiert",
         "description": "Security Headers (CSP, HSTS, X-Frame-Options), Input-Validierung, Rate-Limiting"},
        {"id": "APP.3.2", "name": "Webserver",
         "implemented": True, "partial": True,
         "status": "Teilweise",
         "description": "Flask auf localhost (127.0.0.1), kein öffentlicher Zugriff. Für Produktion: nginx + TLS empfohlen"},
        {"id": "CON.1",   "name": "Kryptokonzept",
         "implemented": vault_ok,
         "status": "Implementiert" if vault_ok else "Ausstehend",
         "description": "AES-256-GCM, PBKDF2-HMAC-SHA256 (600k Iter.), verschlüsselter Key-Vault"},
        {"id": "DER.2.1", "name": "Behandlung von Sicherheitsvorfällen",
         "implemented": inc_ok,
         "status": "Implementiert" if inc_ok else "Ausstehend",
         "description": "Incident Manager, BSI-Meldebogen, DSGVO-Art.33-Timer"},
        {"id": "NET.1.1", "name": "Netzarchitektur",
         "implemented": True,
         "status": "Implementiert",
         "description": "Localhost-Binding, kein externes Routing, Netzwerk-Isolation"},
        {"id": "OPS.1.1.5", "name": "Protokollierung",
         "implemented": audit_ok,
         "status": "Implementiert" if audit_ok else "Ausstehend",
         "description": "HMAC-gesicherte Audit-Logs, Anomalie-Erkennung, Log-Rotation"},
        {"id": "ORP.4",  "name": "Identitäts- und Berechtigungsmanagement",
         "implemented": users_ok,
         "status": "Implementiert" if users_ok else "Ausstehend",
         "description": "RBAC (admin/analyst/viewer/auditor), TOTP-MFA, Session-Management"},
        {"id": "SYS.2.1", "name": "Client-Systeme",
         "implemented": True,
         "status": "Implementiert",
         "description": "Vault-Berechtigungen (chmod 600), API-Keys nie in Klartextdateien"},
        {"id": "OPS.2.2", "name": "Cloud-Nutzung",
         "implemented": True,
         "status": "Implementiert",
         "description": "Anthropic-API: IP-Anonymisierung vor Übertragung. Kein Datentransfer ohne Pseudonymisierung"},
        {"id": "CON.3",  "name": "Datensicherungskonzept",
         "implemented": False,
         "status": "Empfohlen",
         "description": "Scan-History lokal gespeichert. BSI-Empfehlung: 3-2-1-Backup-Regel implementieren"},
    ]

    implemented = sum(1 for b in bausteine if b["implemented"])
    total       = len(bausteine)
    pct         = round(implemented / total * 100)

    return {
        "score":      f"{implemented}/{total}",
        "percentage": pct,
        "bausteine":  bausteine,
        "framework":  "BSI IT-Grundschutz",
        "version":    "BSI IT-Grundschutz Kompendium 2023",
    }


# ── Vorfälle ──────────────────────────────────────────────────────────────────

@compliance_bp.route("/incidents")
def incidents():
    from modules.incident_manager import list_incidents, get_incident_summary
    status_f   = request.args.get("status")
    severity_f = request.args.get("severity")
    return jsonify({
        "incidents": list_incidents(status_f, severity_f),
        "summary":   get_incident_summary(),
    })


@compliance_bp.route("/incidents", methods=["POST"])
def create_incident_api():
    from modules.incident_manager import create_incident, IncidentType, Severity
    data = request.get_json(force=True) or {}
    try:
        inc_id = create_incident(
            IncidentType(data.get("type", "policy_violation")),
            Severity(data.get("severity", "medium")),
            data.get("title", "Unbekannter Vorfall"),
            data.get("description", ""),
            data.get("affected_data"),
            reported_by=data.get("reported_by", "web_api"),
        )
        return jsonify({"incident_id": inc_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@compliance_bp.route("/incidents/<incident_id>/resolve", methods=["POST"])
def resolve_incident_api(incident_id):
    from modules.incident_manager import resolve_incident
    data = request.get_json(force=True) or {}
    ok   = resolve_incident(incident_id, data.get("resolution", ""), data.get("by", "web_api"))
    return jsonify({"ok": ok})


@compliance_bp.route("/incidents/check-integrity", methods=["POST"])
def check_integrity():
    from modules.incident_manager import check_audit_tampering
    inc_id = check_audit_tampering()
    return jsonify({"incident_id": inc_id, "tampering_detected": inc_id is not None})


@compliance_bp.route("/incidents/<incident_id>/bsi-report")
def bsi_report(incident_id):
    from modules.incident_manager import generate_bsi_report
    return jsonify(generate_bsi_report(incident_id))


# ── Audit-Log ──────────────────────────────────────────────────────────────────

@compliance_bp.route("/audit")
def audit_log():
    from modules.audit_logger import read_recent
    n      = int(request.args.get("n", 100))
    level  = request.args.get("level") or None
    cat    = request.args.get("category") or None
    entries = read_recent(n, level_filter=level, category_filter=cat)
    return jsonify({"entries": entries, "count": len(entries)})


@compliance_bp.route("/audit/verify")
def audit_verify():
    from modules.audit_logger import verify_chain
    return jsonify(verify_chain())


@compliance_bp.route("/audit/export", methods=["POST"])
def audit_export():
    from modules.audit_logger import export_audit_log
    ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path  = f"output/audit_export_{ts}.json"
    os.makedirs("output", exist_ok=True)
    count = export_audit_log(path)
    return jsonify({"path": path, "count": count})
