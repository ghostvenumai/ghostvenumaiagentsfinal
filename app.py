# app.py — GhostVenumAI v2.0 Enterprise Flask Backend
import os
import sys
import json
import queue
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from flask_cors import CORS

app = Flask(__name__)

# ── Enterprise Security Setup ──────────────────────────────────────────────────
# Security Headers (ISO 27001 A.8.15, BSI APP.3.1)
try:
    from modules.security_headers import add_security_headers, configure_cors
    app.after_request(add_security_headers)
    configure_cors(app, allowed_origins=[
        "http://localhost:5000", "http://127.0.0.1:5000"
    ])
except ImportError:
    CORS(app)

# Compliance Blueprint (ISO 27001, DSGVO, BSI)
try:
    from modules.compliance_api import compliance_bp
    app.register_blueprint(compliance_bp)
except ImportError as e:
    print(f"[!] Compliance-API nicht geladen: {e}")

# ── Konfiguration ──────────────────────────────────────────────────────────────

CFG_PATH = "config.json"

def load_config() -> dict:
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(data: dict):
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Config-Fehler: {e}")

# ── Routen ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = load_config()
    # API-Keys NICHT zurückgeben (nur ob vorhanden)
    safe = {k: v for k, v in cfg.items() if "key" not in k.lower()}
    safe["has_openai_key"]    = bool(cfg.get("openai_key") or os.getenv("OPENAI_API_KEY"))
    safe["has_anthropic_key"] = bool(cfg.get("anthropic_key") or os.getenv("ANTHROPIC_API_KEY"))
    return jsonify(safe)

@app.route("/api/config", methods=["POST"])
def update_config():
    data    = request.get_json(force=True)
    cfg     = load_config()
    changed = []
    for key in ["target", "nmap_args", "language", "openai_model",
                "claude_model", "openai_key", "anthropic_key"]:
        if key in data and data[key] != "":
            cfg[key] = data[key]
            changed.append(key)

    save_config(cfg)

    # Audit-Log für Konfigurationsänderungen (ISO 27001 A.12.1.2)
    try:
        from modules.audit_logger import log_config_change
        for field in changed:
            safe_val = "***" if "key" in field else data[field]
            log_config_change(field, user="web_api", new_value=safe_val)
    except Exception:
        pass

    return jsonify({"ok": True})

@app.route("/api/sysinfo", methods=["GET"])
def sysinfo():
    from modules.system_info import collect_system_info
    return jsonify(collect_system_info())

# ── Classic Scan ───────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data   = request.get_json(force=True)
    target = data.get("target", "").strip()
    args   = data.get("nmap_args", "-sS -T4 -v -sV").strip()

    if not target:
        return jsonify({"error": "Kein Ziel angegeben."}), 400

    # Input-Validierung (ISO 27001 A.8.28, BSI APP.3.1.A10)
    try:
        from modules.security_headers import validate_ip_or_range, validate_nmap_args
        valid_ip, ip_err = validate_ip_or_range(target)
        if not valid_ip:
            return jsonify({"error": f"Ungültiges Scan-Ziel: {ip_err}"}), 400
        valid_args, args_err = validate_nmap_args(args)
        if not valid_args:
            return jsonify({"error": f"Ungültige Nmap-Argumente: {args_err}"}), 400
    except ImportError:
        pass

    # Audit-Log
    try:
        from modules.audit_logger import log_scan
        log_scan(target, user="web_api", scan_args=args)
    except Exception:
        pass

    from modules.scanner import run_nmap_scan
    output = run_nmap_scan(target, args)

    # Scan automatisch in Historie speichern
    try:
        from modules.memory import save_scan, _parse_ports
        ports   = _parse_ports(output)
        scan_id = save_scan(
            target          = target,
            ports           = ports,
            cves            = [],
            raw_scan        = output,
            raw_cves        = "",
            raw_remediation = "",
            summary         = f"Classic Scan — {len(ports)} offene Port(s)"
        )
    except Exception as e:
        scan_id = None

    # E-Mail-Alert bei kritischen Befunden (ISO 27001 A.16.1)
    try:
        from modules.alerting import send_scan_alert
        send_scan_alert(output, target)
    except Exception:
        pass

    return jsonify({"output": output, "scan_id": scan_id})

@app.route("/api/gpt", methods=["POST"])
def api_gpt():
    data      = request.get_json(force=True)
    scan_out  = data.get("scan_output", "").strip()
    model     = data.get("model", "gpt-4o-mini")

    if not scan_out:
        return jsonify({"error": "Kein Scan-Output vorhanden."}), 400

    from modules.gpt_analysis import analyze_scan_with_gpt
    try:
        path = analyze_scan_with_gpt(scan_out, model=model)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"output": content, "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report", methods=["POST"])
def api_report():
    data     = request.get_json(force=True)
    scan_out = data.get("scan_output", "")

    os.makedirs("output", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/report_{ts}.txt"

    from modules.report import create_report
    try:
        create_report(scan_out, path)
        return jsonify({"path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Agent Mode — Server-Sent Events (SSE) ─────────────────────────────────────

@app.route("/api/agents/stream")
def api_agents_stream():
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Kein Ziel."}), 400

    msg_queue = queue.Queue()

    def log_cb(agent: str, msg: str):
        msg_queue.put({"agent": agent, "content": msg})

    def worker():
        try:
            from modules.agents.orchestrator import run_full_analysis
            summary = run_full_analysis(target, log_callback=log_cb)
            msg_queue.put({"agent": "OrchestratorAgent", "content": summary})
        except Exception as e:
            msg_queue.put({"agent": "OrchestratorAgent", "content": f"FEHLER: {e}"})
        finally:
            msg_queue.put(None)  # Sentinel

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def generate():
        yield "data: {\"status\": \"start\"}\n\n"
        while True:
            item = msg_queue.get()
            if item is None:
                yield "data: {\"status\": \"done\"}\n\n"
                break
            payload = json.dumps(item, ensure_ascii=False)
            yield f"data: {payload}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

# ── History / Memory API ───────────────────────────────────────────────────────

@app.route("/api/history/<target>")
def api_history(target):
    """Gibt alle Scans für ein Target zurück (ohne raw_-Felder)."""
    try:
        from modules.memory import load_all_scans
        scans = load_all_scans(target)
        result = []
        for s in scans:
            result.append({
                "scan_id":    s.get("scan_id", ""),
                "timestamp":  s.get("timestamp", ""),
                "port_count": len(s.get("ports", [])),
                "cve_count":  len(s.get("cves", [])),
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history/<target>/<scan_id>")
def api_history_detail(target, scan_id):
    """Gibt den vollständigen Scan-Datensatz für eine scan_id zurück."""
    try:
        from modules.memory import load_all_scans
        scans = load_all_scans(target)
        for s in scans:
            if s.get("scan_id") == scan_id:
                return jsonify(s)
        return jsonify({"error": "Scan nicht gefunden."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/diff/<target>")
def api_diff(target):
    """Vergleicht die letzten zwei Scans für ein Target."""
    try:
        from modules.memory import load_all_scans, generate_diff
        scans = load_all_scans(target)
        if len(scans) < 2:
            return jsonify({"available": False})
        diff = generate_diff(scans[1], scans[0])  # scans[0] ist der neueste
        return jsonify({"available": True, "diff": diff,
                        "old_timestamp": scans[1].get("timestamp", ""),
                        "new_timestamp": scans[0].get("timestamp", "")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets")
def api_targets():
    """Gibt alle Targets zurück, für die History-Daten existieren."""
    try:
        from modules.memory import list_all_targets
        return jsonify(list_all_targets())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Monitoring ─────────────────────────────────────────────────────────────────

_monitor_engine = None

@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    global _monitor_engine
    from modules.monitor import MonitorEngine
    data         = request.get_json(force=True)
    target       = data.get("target", "").strip()
    interval_min = int(data.get("interval_min", 60))
    nmap_args    = data.get("nmap_args", "-sV -T4 --open").strip()

    if not target:
        return jsonify({"error": "Kein Ziel angegeben."}), 400

    if _monitor_engine and _monitor_engine.is_running:
        return jsonify({"error": "Monitoring läuft bereits."}), 400

    _monitor_engine = MonitorEngine()

    msg_queue = queue.Queue()

    def on_log(msg):
        msg_queue.put({"type": "log", "content": msg})

    def on_change(diff, raw_scan):
        msg_queue.put({"type": "change", "diff": {
            "new_ports":    [f"{p['port']}/{p['proto']} {p.get('service','')}" for p in diff["ports"]["new"]],
            "closed_ports": [f"{p['port']}/{p['proto']}" for p in diff["ports"]["closed"]],
            "versions":     diff.get("version_changes", []),
            "summary":      diff.get("summary", ""),
        }})
        try:
            from modules.agents.orchestrator import run_full_analysis
            summary = run_full_analysis(target, log_callback=lambda a, m: on_log(f"[{a}] {m}"))
            msg_queue.put({"type": "log", "content": f"[OrchestratorAgent] {summary}"})
        except Exception as e:
            msg_queue.put({"type": "log", "content": f"[ERR] KI-Analyse fehlgeschlagen: {e}"})

    _monitor_engine.start(target=target, interval_min=interval_min,
                          nmap_args=nmap_args, on_log=on_log, on_change=on_change)

    # SSE-Stream zurückgeben
    def generate():
        yield f"data: {json.dumps({'type':'started','target':target})}\n\n"
        while _monitor_engine and _monitor_engine.is_running:
            try:
                item = msg_queue.get(timeout=2)
                # Status-Update hinzufügen
                item["status"] = _monitor_engine.status()
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            except Exception:
                # Heartbeat
                if _monitor_engine:
                    st = _monitor_engine.status()
                    yield f"data: {json.dumps({'type':'heartbeat','status':st})}\n\n"
        yield f"data: {json.dumps({'type':'stopped'})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    global _monitor_engine
    if _monitor_engine:
        _monitor_engine.stop()
    return jsonify({"ok": True})


@app.route("/api/monitor/status")
def api_monitor_status():
    global _monitor_engine
    if not _monitor_engine:
        return jsonify({"running": False})
    return jsonify(_monitor_engine.status())


# ── Einstiegspunkt ─────────────────────────────────────────────────────────────

@app.route("/compliance")
def compliance_dashboard():
    return render_template("compliance.html")


# ── Benutzerverwaltung API ─────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
def api_users_list():
    try:
        from modules.rbac import list_users
        return jsonify({"users": list_users()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
def api_users_create():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "viewer").strip()

    if not username or not password:
        return jsonify({"error": "Benutzername und Passwort erforderlich."}), 400
    if len(password) < 8:
        return jsonify({"error": "Passwort muss mindestens 8 Zeichen haben."}), 400

    try:
        from modules.rbac import create_user
        result = create_user(username, password, role, created_by="web_admin")
        return jsonify({"ok": True, "user": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>", methods=["DELETE"])
def api_users_delete(username):
    try:
        from modules.rbac import delete_user
        ok = delete_user(username, deleted_by="web_admin")
        if not ok:
            return jsonify({"error": "Benutzer nicht gefunden."}), 404
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/role", methods=["PATCH"])
def api_users_role(username):
    data = request.get_json(force=True) or {}
    new_role = data.get("role", "").strip()
    if not new_role:
        return jsonify({"error": "Rolle erforderlich."}), 400
    try:
        from modules.rbac import ROLES, _load_users, _save_users
        if new_role not in ROLES:
            return jsonify({"error": f"Ungültige Rolle: {new_role}"}), 400
        users = _load_users()
        if username not in users:
            return jsonify({"error": "Benutzer nicht gefunden."}), 404
        users[username]["role"] = new_role
        _save_users(users)
        return jsonify({"ok": True, "username": username, "role": new_role})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/totp/setup/<username>", methods=["POST"])
def api_totp_setup(username):
    try:
        from modules.rbac import setup_totp
        result = setup_totp(username)
        if not result:
            return jsonify({"error": "Benutzer nicht gefunden."}), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Alert / SMTP API ───────────────────────────────────────────────────────────

@app.route("/api/alerts/test", methods=["POST"])
def api_alert_test():
    try:
        from modules.alerting import smtp_test
        return jsonify(smtp_test())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/backup/create", methods=["POST"])
def api_backup_create():
    from modules.backup import create_backup
    data  = request.get_json(force=True) or {}
    label = data.get("label", "manual")
    return jsonify(create_backup(label))


@app.route("/api/backup/list")
def api_backup_list():
    from modules.backup import list_backups
    return jsonify({"backups": list_backups()})


@app.route("/api/backup/verify/<filename>")
def api_backup_verify(filename):
    from modules.backup import verify_backup
    return jsonify(verify_backup(filename))


@app.route("/api/backup/cleanup", methods=["POST"])
def api_backup_cleanup():
    from modules.backup import cleanup_old_backups
    return jsonify(cleanup_old_backups())


@app.route("/api/alerts/smtp", methods=["POST"])
def api_alert_smtp_save():
    data = request.get_json(force=True) or {}
    cfg  = load_config()
    cfg.setdefault("enterprise", {}).setdefault("notifications", {})["smtp"] = {
        "host":     data.get("host", ""),
        "port":     int(data.get("port", 587)),
        "user":     data.get("user", ""),
        "password": data.get("password", ""),
        "from":     data.get("from", ""),
        "to":       data.get("to", ""),
    }
    save_config(cfg)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # System-Start auditieren
    try:
        from modules.audit_logger import log_system_event
        log_system_event("application_start", {"version": "2.0-Enterprise", "host": "127.0.0.1:5000"})
    except Exception:
        pass

    print("\n👻 GhostVenumAI v2.0 — Enterprise Edition")
    print("🌐 Web-GUI:         http://localhost:5000")
    print("🛡️  Compliance:     http://localhost:5000/compliance")
    print("─" * 50)
    print("  ISO 27001 | DSGVO | BSI IT-Grundschutz")
    print("─" * 50)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
