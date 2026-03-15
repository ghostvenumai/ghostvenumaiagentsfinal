# app.py — GhostVenumAI v2.0 Flask Backend
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
CORS(app)

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
    data = request.get_json(force=True)
    cfg  = load_config()
    for key in ["target", "nmap_args", "language", "openai_model",
                "claude_model", "openai_key", "anthropic_key"]:
        if key in data and data[key] != "":
            cfg[key] = data[key]
    save_config(cfg)
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

    from modules.scanner import run_nmap_scan
    output = run_nmap_scan(target, args)
    return jsonify({"output": output})

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


# ── Einstiegspunkt ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n👻 GhostVenumAI v2.0 — Agent Edition")
    print("🌐 Web-GUI startet auf: http://localhost:5000")
    print("─" * 40)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
