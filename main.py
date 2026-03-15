#!/usr/bin/env python3
# main.py — GhostVenumAI v2.0 Agent Edition
import os
import sys
import json
import argparse
import webbrowser
import threading
import time

# ── SSH-Gate ───────────────────────────────────────────────────────────────────
from modules.auth import is_ssh_session, require_password

if is_ssh_session():
    if not require_password():
        print("❌ Zugriff verweigert.")
        sys.exit(1)

# ── CLI-Argumente ──────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="GhostVenumAI v2.0 — Defensives Netzwerk-Analyse-Tool"
)
parser.add_argument("--agents", action="store_true", help="Agent-Modus (CLI, kein GUI)")
parser.add_argument("--target", type=str,            help="Ziel-IP oder Hostname")
parser.add_argument("--model",  type=str, default="claude-sonnet-4-6",
                    help="Claude-Modell (z.B. claude-sonnet-4-6)")
parser.add_argument("--port",   type=int, default=5000,
                    help="Port für Web-GUI (Standard: 5000)")
parser.add_argument("--no-browser", action="store_true",
                    help="Browser nicht automatisch öffnen")
args = parser.parse_args()

# ── Config laden ───────────────────────────────────────────────────────────────
cfg = {}
try:
    with open("config.json", "r", encoding="utf-8") as f:
        cfg = json.load(f)
except Exception:
    pass

TARGET_IP = args.target or cfg.get("target", "")

# ── Agent-Modus (CLI, kein GUI) ───────────────────────────────────────────────
if args.agents:
    if not TARGET_IP:
        print("❌ Kein Ziel angegeben. Nutze --target <IP>")
        sys.exit(1)

    print(f"\n👻 GhostVenumAI v2.0 — Agent Edition (CLI)")
    print(f"🎯 Ziel:   {TARGET_IP}")
    print(f"🤖 Modell: {args.model}")
    print("─" * 52)

    from modules.agents.orchestrator import run_full_analysis

    def log_cb(agent: str, msg: str):
        print(f"[{agent}] {msg}")

    try:
        summary = run_full_analysis(TARGET_IP, log_callback=log_cb)
        print("\n" + "═" * 52)
        print(summary)
        print("═" * 52)
    except KeyboardInterrupt:
        print("\n[!] Abgebrochen.")
    except Exception as e:
        print(f"\n❌ Fehler: {e}")

    sys.exit(0)

# ── Web-GUI (Standard) ────────────────────────────────────────────────────────
print("\n👻 GhostVenumAI v2.0 — Agent Edition")
print(f"🌐 Web-GUI: http://localhost:{args.port}")
print("─" * 40)

if not args.no_browser:
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://localhost:{args.port}")
    threading.Thread(target=open_browser, daemon=True).start()

from app import app
app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
