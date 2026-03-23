#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cli.py — GhostVenumAI CLI Agent Mode
"""
Kommandozeilen-Einstiegspunkt für GhostVenumAI.
Nutzt dieselben Agenten wie der GUI Agent-Mode-Tab — kein Code doppelt.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MODUS 1: Einmalige Vollanalyse
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python cli.py analyze --target 192.168.178.1
  python cli.py analyze --target 192.168.178.0/24 --model claude-opus-4-6
  python cli.py analyze --target 192.168.178.1 --output bericht.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MODUS 2: 24/7 Monitoring (dauerhafter Hintergrundbetrieb)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python cli.py monitor --target 192.168.178.0/24
  python cli.py monitor --target 192.168.178.0/24 --interval 30
  python cli.py monitor --target 192.168.178.0/24 --interval 60 --nmap-args "-sV -T4"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Optionen (beide Modi)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --target     Ziel-IP oder Netzwerk-Range  (Pflicht)
  --model      Claude-Modell                (Standard: claude-sonnet-4-6)
  --nmap-args  Nmap-Parameter               (Standard: -sV -T4 --open)
  --output     Ausgabedatei für Bericht     (optional, nur analyze)
  --interval   Minuten zwischen Scans       (Standard: 60, nur monitor)
  --no-color   Farbige Ausgabe deaktivieren
"""

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

# Projektverzeichnis in Pfad aufnehmen
_ROOT = Path(__file__).parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ── ANSI-Farben ───────────────────────────────────────────────────────────────

class C:
    """ANSI-Farbcodes. Werden deaktiviert wenn --no-color gesetzt."""
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    ORCH   = "\033[35m"   # lila   — OrchestratorAgent
    RECON  = "\033[34m"   # blau   — ReconAgent
    VULN   = "\033[33m"   # gelb   — VulnAgent
    REMED  = "\033[32m"   # grün   — RemediationAgent
    ERR    = "\033[31m"   # rot    — Fehler
    INFO   = "\033[36m"   # cyan   — Info
    DIM    = "\033[2m"    # gedimmt
    OK     = "\033[32m"   # grün
    WARN   = "\033[33m"   # gelb
    CHANGE = "\033[33;1m" # gelb+fett — Änderung erkannt
    HEADER = "\033[35;1m" # lila+fett

_AGENT_COLOR = {
    "OrchestratorAgent": C.ORCH,
    "ReconAgent":        C.RECON,
    "VulnAgent":         C.VULN,
    "RemediationAgent":  C.REMED,
}

_USE_COLOR = True


def _strip_color(text: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


def cprint(text: str, color: str = "", end: str = "\n"):
    if _USE_COLOR and color:
        print(f"{color}{text}{C.RESET}", end=end)
    else:
        print(_strip_color(text) if not _USE_COLOR else text, end=end)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log(agent: str, msg: str):
    color  = _AGENT_COLOR.get(agent, C.INFO)
    prefix = f"{C.DIM}[{_ts()}]{C.RESET} {color}[{agent}]{C.RESET} "
    if _USE_COLOR:
        print(f"{prefix}{msg}")
    else:
        print(f"[{_ts()}] [{agent}] {msg}")


def _banner():
    cprint("""
┌─────────────────────────────────────────────────────┐
│         👻  GhostVenumAI  —  CLI Agent Mode         │
│           Defensives Netzwerk-Analyse-Tool           │
└─────────────────────────────────────────────────────┘""", C.HEADER)


def _separator(title: str = ""):
    line = "━" * 54
    if title:
        cprint(f"\n{line}", C.DIM)
        cprint(f"  {title}", C.BOLD)
        cprint(f"{line}", C.DIM)
    else:
        cprint(line, C.DIM)


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    cfg_path = _ROOT / "config.json"
    try:
        return json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _check_anthropic_key(cfg: dict) -> str:
    key = (
        os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("GVA_ANTHROPIC_KEY")
        or cfg.get("anthropic_key", "")
    )
    if not key:
        cprint("\n❌  Kein Anthropic API-Key gefunden.", C.ERR)
        cprint("    Setze ihn als Umgebungsvariable:", C.DIM)
        cprint("    export ANTHROPIC_API_KEY=sk-ant-...", C.INFO)
        cprint("    oder trage ihn in config.json ein:", C.DIM)
        cprint('    { "anthropic_key": "sk-ant-..." }', C.INFO)
        sys.exit(1)
    return key


# ── Modus 1: analyze ─────────────────────────────────────────────────────────

def cmd_analyze(args, cfg: dict):
    """Einmalige Vollanalyse mit allen 4 Agenten."""
    _banner()
    _separator(f"Vollanalyse: {args.target}")
    cprint(f"  Modell:     {args.model}", C.DIM)
    cprint(f"  Nmap-Args:  {args.nmap_args}", C.DIM)
    cprint(f"  Gestartet:  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}", C.DIM)

    _check_anthropic_key(cfg)

    # Claude-Modell in Config setzen (Orchestrator liest config.json)
    cfg["claude_model"] = args.model
    cfg_path = _ROOT / "config.json"
    try:
        cfg_path.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    output_lines = []

    def log_cb(agent: str, msg: str):
        _log(agent, msg)
        output_lines.append(f"[{agent}] {msg}")

    from modules.agents.orchestrator import run_full_analysis

    cprint("\n", end="")
    try:
        summary = run_full_analysis(args.target, log_callback=log_cb)
    except KeyboardInterrupt:
        cprint("\n\n⛔  Analyse abgebrochen.", C.WARN)
        sys.exit(0)
    except Exception as e:
        cprint(f"\n❌  Analyse fehlgeschlagen: {e}", C.ERR)
        sys.exit(1)

    # Zusammenfassung ausgeben
    _separator("Management-Summary")
    cprint(summary, C.OK)
    _separator()

    # Optional: in Datei speichern
    if args.output:
        out = Path(args.output)
        content = "\n".join(output_lines) + "\n\n" + summary
        out.write_text(content, encoding="utf-8")
        cprint(f"\n💾  Bericht gespeichert: {out.resolve()}", C.INFO)

    cprint("\n✅  Vollanalyse abgeschlossen.\n", C.OK)


# ── Modus 2: monitor ─────────────────────────────────────────────────────────

def cmd_monitor(args, cfg: dict):
    """24/7 Monitoring-Modus — läuft bis Ctrl+C."""
    _banner()
    _separator(f"Monitoring: {args.target}")
    cprint(f"  Intervall:  {args.interval} Minuten", C.DIM)
    cprint(f"  Nmap-Args:  {args.nmap_args}", C.DIM)
    cprint(f"  Modell:     {args.model}", C.DIM)
    cprint(f"  Gestartet:  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}", C.DIM)
    cprint("  Stoppen:    Ctrl+C\n", C.DIM)

    _check_anthropic_key(cfg)

    # Claude-Modell in Config setzen
    cfg["claude_model"] = args.model
    cfg_path = _ROOT / "config.json"
    try:
        cfg_path.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    from modules.monitor import MonitorEngine
    from modules.agents.orchestrator import run_full_analysis

    engine = MonitorEngine()

    def on_log(msg: str):
        cprint(f"[{_ts()}] {msg}", C.INFO if "✅" not in msg else C.OK)

    def on_change(diff: dict, raw_scan: str):
        _separator("⚠️  ÄNDERUNG ERKANNT")

        if diff["ports"]["new"]:
            for p in diff["ports"]["new"]:
                cprint(f"  🔴 Neuer Port:     {p['port']}/{p['proto']} "
                       f"({p.get('service','')} {p.get('version','')})", C.CHANGE)
        if diff["ports"]["closed"]:
            for p in diff["ports"]["closed"]:
                cprint(f"  🟡 Port geschlossen: {p['port']}/{p['proto']} "
                       f"({p.get('service','')})", C.WARN)
        if diff.get("version_changes"):
            for vc in diff["version_changes"]:
                cprint(f"  🔵 Version geändert: {vc['port']} {vc['service']} "
                       f"{vc['old_version']} → {vc['new_version']}", C.CHANGE)

        cprint("\n🤖  Starte KI-Vollanalyse...\n", C.INFO)
        try:
            summary = run_full_analysis(
                args.target,
                log_callback=lambda agent, msg: _log(agent, msg)
            )
            _separator("Management-Summary")
            cprint(summary, C.OK)
            _separator()
        except Exception as e:
            cprint(f"❌  KI-Analyse fehlgeschlagen: {e}", C.ERR)

    # Sauberes Beenden mit Ctrl+C
    def _sigint(sig, frame):
        cprint("\n\n⛔  Monitoring gestoppt.", C.WARN)
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    engine.start(
        target       = args.target,
        interval_min = args.interval,
        nmap_args    = args.nmap_args,
        on_log       = on_log,
        on_change    = on_change,
    )

    # Hauptthread am Leben halten
    while engine.is_running:
        time.sleep(1)


# ── Argument-Parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostvenumai",
        description="GhostVenumAI — Defensives Netzwerk-Analyse-Tool (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--no-color", action="store_true",
                        help="Farbige Ausgabe deaktivieren")

    sub = parser.add_subparsers(dest="cmd", metavar="MODUS")
    sub.required = True

    # ── analyze ──────────────────────────────────────────────────────────────
    p_analyze = sub.add_parser(
        "analyze",
        help="Einmalige Vollanalyse (Recon → CVE → Remediation → Summary)",
    )
    p_analyze.add_argument(
        "--target", required=True,
        metavar="IP/RANGE",
        help="Ziel-IP oder Netzwerk-Range (z.B. 192.168.1.1 oder 192.168.1.0/24)",
    )
    p_analyze.add_argument(
        "--model", default="claude-sonnet-4-6",
        metavar="MODELL",
        help="Claude-Modell (Standard: claude-sonnet-4-6)",
    )
    p_analyze.add_argument(
        "--nmap-args", default="-sV -T4",
        metavar="ARGS",
        help='Nmap-Parameter (Standard: "-sV -T4")',
    )
    p_analyze.add_argument(
        "--output", default="",
        metavar="DATEI",
        help="Bericht in Datei speichern (optional)",
    )

    # ── monitor ──────────────────────────────────────────────────────────────
    p_monitor = sub.add_parser(
        "monitor",
        help="24/7 Monitoring — läuft dauerhaft, KI-Analyse nur bei Änderung",
    )
    p_monitor.add_argument(
        "--target", required=True,
        metavar="IP/RANGE",
        help="Ziel-IP oder Netzwerk-Range",
    )
    p_monitor.add_argument(
        "--interval", type=int, default=60,
        metavar="MINUTEN",
        help="Minuten zwischen Scans (Standard: 60, Minimum: 5)",
    )
    p_monitor.add_argument(
        "--model", default="claude-sonnet-4-6",
        metavar="MODELL",
        help="Claude-Modell für KI-Analyse bei Änderung",
    )
    p_monitor.add_argument(
        "--nmap-args", default="-sV -T4 --open",
        metavar="ARGS",
        help='Nmap-Parameter (Standard: "-sV -T4 --open")',
    )

    return parser


# ── Einstiegspunkt ────────────────────────────────────────────────────────────

def main():
    global _USE_COLOR

    parser = _build_parser()
    args   = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    cfg = _load_config()

    if args.cmd == "analyze":
        cmd_analyze(args, cfg)
    elif args.cmd == "monitor":
        cmd_monitor(args, cfg)


if __name__ == "__main__":
    main()
