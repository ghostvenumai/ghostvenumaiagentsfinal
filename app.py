# app.py — GhostVenumAI v2.0 Enterprise Flask Backend
import os
import sys
import json
import queue
import threading
import subprocess
from functools import wraps
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

# ── Authentifizierung & Autorisierung (RBAC) ───────────────────────────────────
# Bindet das vorhandene RBAC-System (modules/rbac.py) an die Web-API.
# Jede zustandsändernde oder sensible Route erfordert eine gültige Session mit
# passender Berechtigung. ISO 27001 A.9.4.1 | BSI APP.3.1.A1

def _extract_token() -> str:
    """Liest das Session-Token aus Header, Authorization-Bearer oder Query-Param.
    Der Query-Param wird für SSE-Routen benötigt, da EventSource im Browser
    keine eigenen HTTP-Header setzen kann."""
    token = request.headers.get("X-Session-Token", "")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        token = request.args.get("token", "")
    return token.strip()


def require_auth(permission: str):
    """Decorator: erzwingt gültige Session + Berechtigung für eine Route.

    401 → nicht authentifiziert / Session abgelaufen
    403 → authentifiziert, aber Berechtigung fehlt
    503 → RBAC-Modul nicht verfügbar (sicherer Default: Zugriff verweigert)
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                from modules.rbac import require_permission
            except ImportError:
                return jsonify({"error": "RBAC-Modul nicht verfügbar — Zugriff verweigert."}), 503
            try:
                session = require_permission(_extract_token(), permission)
            except PermissionError as e:
                code = 401 if "authentifiziert" in str(e).lower() else 403
                return jsonify({"error": str(e)}), code
            # Authentifizierten Benutzer für Audit-Logs verfügbar machen
            request.gva_user = session.get("username", "unknown")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _current_user() -> str:
    """Authentifizierter Benutzer der aktuellen Anfrage (für Audit-Logs)."""
    return getattr(request, "gva_user", "web_api")


# ── Verschlüsselter Secret-Speicher (Vault) ────────────────────────────────────
# Secrets (API-Keys, SMTP-Passwort) gehören NICHT im Klartext in config.json,
# sondern in den AES-256-GCM-Vault (modules/key_manager.py). ISO 27001 A.10

# config.json-Feld → Vault-/Env-Name für secret-pflichtige Felder
SECRET_FIELDS = {
    "openai_key":    "OPENAI_API_KEY",
    "anthropic_key": "ANTHROPIC_API_KEY",
}

def _vault():
    """Gibt das key_manager-Modul zurück, wenn ein entsperrter Vault nutzbar ist
    (VAULT_PASSWORD gesetzt + pycryptodome verfügbar), sonst None."""
    try:
        from modules import key_manager
    except Exception:
        return None
    return key_manager if key_manager.vault_available() else None

# ── Routen ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Login / Session ─────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    totp     = data.get("totp_code", "").strip()

    if not username or not password:
        return jsonify({"error": "Benutzername und Passwort erforderlich."}), 400

    try:
        from modules.rbac import authenticate, get_session
    except ImportError:
        return jsonify({"error": "RBAC-Modul nicht verfügbar."}), 503

    token = authenticate(username, password, totp_code=totp,
                         source_ip=request.remote_addr or "127.0.0.1")
    if not token:
        # Bewusst generische Fehlermeldung (keine User-Enumeration)
        return jsonify({"error": "Anmeldung fehlgeschlagen."}), 401

    session = get_session(token) or {}
    return jsonify({
        "token":      token,
        "username":   username,
        "role":       session.get("role", ""),
        "expires_in": 3600,
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    try:
        from modules.rbac import logout
        logout(_extract_token())
    except ImportError:
        pass
    return jsonify({"ok": True})


@app.route("/api/whoami")
def api_whoami():
    try:
        from modules.rbac import get_session
    except ImportError:
        return jsonify({"authenticated": False}), 503
    session = get_session(_extract_token())
    if not session:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "username":      session.get("username", ""),
        "role":          session.get("role", ""),
    })

@app.route("/api/config", methods=["GET"])
@require_auth("config:read")
def get_config():
    cfg = load_config()
    # API-Keys NICHT zurückgeben (nur ob vorhanden — auch aus dem Vault)
    safe = {k: v for k, v in cfg.items() if "key" not in k.lower()}
    km = _vault()
    has_openai    = bool(cfg.get("openai_key") or os.getenv("OPENAI_API_KEY"))
    has_anthropic = bool(cfg.get("anthropic_key") or os.getenv("ANTHROPIC_API_KEY"))
    if km:
        has_openai    = has_openai    or bool(km.get_secret("OPENAI_API_KEY"))
        has_anthropic = has_anthropic or bool(km.get_secret("ANTHROPIC_API_KEY"))
    safe["has_openai_key"]    = has_openai
    safe["has_anthropic_key"] = has_anthropic
    safe["vault_unlocked"]    = km is not None
    return jsonify(safe)

@app.route("/api/config", methods=["POST"])
@require_auth("config:write")
def update_config():
    data    = request.get_json(force=True)
    cfg     = load_config()
    changed = []
    km      = _vault()
    for key in ["target", "nmap_args", "language", "openai_model",
                "claude_model", "openai_key", "anthropic_key"]:
        if key not in data or data[key] == "":
            continue
        if key in SECRET_FIELDS and km:
            # API-Key verschlüsselt im Vault ablegen, niemals im Klartext in config.json
            km.store_secret(SECRET_FIELDS[key], data[key])
            cfg.pop(key, None)
        else:
            if key in SECRET_FIELDS:
                print(f"[!] Kein Vault entsperrt — '{key}' wird im Klartext gespeichert. "
                      f"Setze VAULT_PASSWORD für verschlüsselte Speicherung.")
            cfg[key] = data[key]
        changed.append(key)

    save_config(cfg)

    # Audit-Log für Konfigurationsänderungen (ISO 27001 A.12.1.2)
    try:
        from modules.audit_logger import log_config_change
        for field in changed:
            safe_val = "***" if "key" in field else data[field]
            log_config_change(field, user=_current_user(), new_value=safe_val)
    except Exception:
        pass

    return jsonify({"ok": True})

@app.route("/api/sysinfo", methods=["GET"])
@require_auth("config:read")
def sysinfo():
    from modules.system_info import collect_system_info
    return jsonify(collect_system_info())

# ── Classic Scan ───────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@require_auth("scan:run")
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
        log_scan(target, user=_current_user(), scan_args=args)
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
@require_auth("report:create")
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
@require_auth("report:create")
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
@require_auth("scan:run")
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
@require_auth("history:view")
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
@require_auth("history:view")
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
@require_auth("history:view")
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
@require_auth("history:view")
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
@require_auth("monitor:start")
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
@require_auth("monitor:stop")
def api_monitor_stop():
    global _monitor_engine
    if _monitor_engine:
        _monitor_engine.stop()
    return jsonify({"ok": True})


@app.route("/api/monitor/status")
@require_auth("monitor:view")
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
@require_auth("users:manage")
def api_users_list():
    try:
        from modules.rbac import list_users
        return jsonify({"users": list_users()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
@require_auth("users:manage")
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
        result = create_user(username, password, role, created_by=_current_user())
        return jsonify({"ok": True, "user": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>", methods=["DELETE"])
@require_auth("users:manage")
def api_users_delete(username):
    try:
        from modules.rbac import delete_user
        ok = delete_user(username, deleted_by=_current_user())
        if not ok:
            return jsonify({"error": "Benutzer nicht gefunden."}), 404
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/role", methods=["PATCH"])
@require_auth("users:manage")
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
@require_auth("users:manage")
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
@require_auth("config:write")
def api_alert_test():
    try:
        from modules.alerting import smtp_test
        return jsonify(smtp_test())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/backup/create", methods=["POST"])
@require_auth("config:write")
def api_backup_create():
    from modules.backup import create_backup
    data  = request.get_json(force=True) or {}
    label = data.get("label", "manual")
    return jsonify(create_backup(label))


@app.route("/api/backup/list")
@require_auth("config:read")
def api_backup_list():
    from modules.backup import list_backups
    return jsonify({"backups": list_backups()})


@app.route("/api/backup/verify/<filename>")
@require_auth("config:read")
def api_backup_verify(filename):
    from modules.backup import verify_backup
    return jsonify(verify_backup(filename))


@app.route("/api/backup/cleanup", methods=["POST"])
@require_auth("config:write")
def api_backup_cleanup():
    from modules.backup import cleanup_old_backups
    return jsonify(cleanup_old_backups())


@app.route("/api/alerts/smtp", methods=["POST"])
@require_auth("config:write")
def api_alert_smtp_save():
    data = request.get_json(force=True) or {}
    cfg  = load_config()
    km   = _vault()

    smtp = {
        "host": data.get("host", ""),
        "port": int(data.get("port", 587)),
        "user": data.get("user", ""),
        "from": data.get("from", ""),
        "to":   data.get("to", ""),
    }

    password = data.get("password", "")
    if password:
        if km:
            # SMTP-Passwort verschlüsselt im Vault, nicht im Klartext in config.json
            km.store_secret("SMTP_PASSWORD", password)
            smtp["password_in_vault"] = True
        else:
            print("[!] Kein Vault entsperrt — SMTP-Passwort wird im Klartext gespeichert. "
                  "Setze VAULT_PASSWORD für verschlüsselte Speicherung.")
            smtp["password"] = password

    cfg.setdefault("enterprise", {}).setdefault("notifications", {})["smtp"] = smtp
    save_config(cfg)
    return jsonify({"ok": True, "vault": km is not None})


if __name__ == "__main__":
    # System-Start auditieren
    try:
        from modules.audit_logger import log_system_event
        log_system_event("application_start", {"version": "2.0-Enterprise", "host": "127.0.0.1:5000"})
    except Exception:
        pass

    # Warnung, falls noch kein Benutzer existiert — die API ist sonst gesperrt
    try:
        from modules.rbac import _load_users
        if not _load_users():
            print("\n[!] Kein Benutzer angelegt — die Web-API ist vollständig gesperrt.")
            print("    Admin anlegen mit:  python -m modules.rbac init-admin")
    except Exception:
        pass

    # Vault entsperren (falls VAULT_PASSWORD gesetzt) → Secrets als Env verfügbar
    try:
        from modules import key_manager
        if key_manager.vault_available():
            if key_manager.vault_status().get("vault_exists"):
                key_manager.load_keys_to_env(key_manager.vault_password())
                print("[Vault] 🔓 Secrets aus verschlüsseltem Vault geladen.")
            else:
                print("[Vault] 🔑 VAULT_PASSWORD gesetzt — neue Secrets werden verschlüsselt gespeichert.")
        else:
            print("[Vault] ⚠️  Kein VAULT_PASSWORD gesetzt — Secrets würden im Klartext in config.json landen.")
    except Exception:
        pass

    print("\n👻 GhostVenumAI v2.0 — Enterprise Edition")
    print("🌐 Web-GUI:         http://localhost:5000")
    print("🛡️  Compliance:     http://localhost:5000/compliance")
    print("🔐 Login:           POST /api/login  (Session via RBAC)")
    print("─" * 50)
    print("  ISO 27001 | DSGVO | BSI IT-Grundschutz")
    print("─" * 50)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
