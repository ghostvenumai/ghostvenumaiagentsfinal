# modules/agents/orchestrator.py
"""
OrchestratorAgent — Koordiniert ReconAgent → VulnAgent → RemediationAgent.
Nutzt Claude (Anthropic SDK). Handoffs werden als sequentielle Aufrufe implementiert.
"""
import os
import sys
from typing import Iterator

try:
    import anthropic
except ImportError:
    raise ImportError("anthropic SDK nicht installiert. Bitte: pip install anthropic")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from . import recon_agent, vuln_agent, remediation_agent
from modules import memory

SYSTEM_PROMPT = """Du bist OrchestratorAgent — Koordinator für GhostVenumAI.

Du koordinierst eine vollständige defensive Sicherheitsanalyse und erstellst am Ende
eine Management-Summary.

Format der Management-Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GhostVenumAI — Analyse-Zusammenfassung
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ziel:              <IP/Hostname>
Gescannte Hosts:   <Anzahl>
Offene Ports:      <Anzahl>
Gefundene CVEs:    <Gesamt> (Kritisch: X | Hoch: X | Mittel: X)
Report gespeichert: <Pfad>

Top-3 dringendste Maßnahmen:
  1. <Wichtigste Maßnahme>
  2. <Zweitwichtigste>
  3. <Drittwichtigste>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""


def _get_client() -> anthropic.Anthropic:
    key = (
        os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("GVA_ANTHROPIC_KEY")
        or _key_from_config()
    )
    if not key:
        raise RuntimeError(
            "Kein Anthropic API-Key gefunden.\n"
            "Setze ANTHROPIC_API_KEY (Umgebungsvariable) oder 'anthropic_key' in config.json."
        )
    return anthropic.Anthropic(api_key=key)


def _key_from_config() -> str | None:
    try:
        import json
        cfg_path = os.path.join(_ROOT, "config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f).get("anthropic_key")
    except Exception:
        return None


def _get_model() -> str:
    try:
        import json
        cfg_path = os.path.join(_ROOT, "config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f).get("claude_model", "claude-sonnet-4-6")
    except Exception:
        return "claude-sonnet-4-6"


def run_full_analysis(target: str, log_callback=None) -> str:
    """
    Führt die vollständige Analyse durch:
    ReconAgent → VulnAgent → RemediationAgent → OrchestratorAgent Summary.

    log_callback: Optional[Callable[[str, str], None]] — (agent_name, message)
                  Wird für Live-Logging in der GUI genutzt.
    """
    client = _get_client()
    model  = _get_model()

    def _log(agent: str, msg: str):
        if log_callback:
            log_callback(agent, msg)
        else:
            print(f"[{agent}] {msg}")

    # ── Vorheriger Scan prüfen (Memory) ───────────────────────────────────────
    old_scan = None
    try:
        old_scan = memory.load_last_scan(target)
        if old_scan:
            _log("OrchestratorAgent",
                 f"Vorheriger Scan gefunden: {old_scan['timestamp']} — erstelle Vergleich...")
    except Exception as e:
        _log("OrchestratorAgent", f"Memory-Laden fehlgeschlagen (nicht kritisch): {e}")

    # ── Schritt 1: ReconAgent ─────────────────────────────────────────────────
    _log("OrchestratorAgent", f"Starte Analyse für: {target}")
    _log("ReconAgent", "Ping-Check und Nmap-Scan werden gestartet...")

    scan_output = ""
    try:
        scan_output = recon_agent.run(target, client, model)
        _log("ReconAgent", f"Scan abgeschlossen. ({len(scan_output)} Zeichen Output)")
    except Exception as e:
        _log("ReconAgent", f"FEHLER: {e}")
        _log("OrchestratorAgent", "ReconAgent fehlgeschlagen — fahre ohne Scan-Daten fort.")

    # ── Schritt 2: VulnAgent ──────────────────────────────────────────────────
    _log("VulnAgent", "Starte CVE-Analyse...")

    cve_output = ""
    if scan_output:
        try:
            cve_output = vuln_agent.run(scan_output, client, model)
            _log("VulnAgent", f"CVE-Analyse abgeschlossen. ({len(cve_output)} Zeichen)")
        except Exception as e:
            _log("VulnAgent", f"FEHLER: {e}")
            _log("OrchestratorAgent", "VulnAgent fehlgeschlagen — fahre ohne CVE-Daten fort.")
    else:
        _log("VulnAgent", "Kein Scan-Output verfügbar — CVE-Analyse übersprungen.")

    # ── Schritt 3: RemediationAgent ───────────────────────────────────────────
    _log("RemediationAgent", "Generiere Fix-Empfehlungen...")

    remed_output = ""
    input_for_remed = cve_output or scan_output or f"Ziel: {target} — keine Scan-Daten verfügbar."
    try:
        remed_output = remediation_agent.run(input_for_remed, client, model)
        _log("RemediationAgent", "Fix-Empfehlungen generiert und gespeichert.")
    except Exception as e:
        _log("RemediationAgent", f"FEHLER: {e}")
        _log("OrchestratorAgent", "RemediationAgent fehlgeschlagen.")

    # ── Schritt 4: Orchestrator-Summary ──────────────────────────────────────
    _log("OrchestratorAgent", "Erstelle Management-Summary...")

    # Diff-Info für Summary vorbereiten
    diff_section = ""
    diff_result  = None
    if old_scan:
        try:
            # Temporären neuen Scan-Dict für Diff zusammenbauen
            temp_new = {
                "ports": memory._parse_ports(scan_output),
                "cves":  memory._parse_cves(cve_output)
            }
            diff_result = memory.generate_diff(old_scan, temp_new)
            diff_section = (
                f"\n\n=== VERGLEICH MIT VORIGEM SCAN ({old_scan['timestamp']}) ===\n"
                f"{diff_result['summary']}\n"
                f"Neue Ports: {len(diff_result['ports']['new'])} | "
                f"Geschlossene Ports: {len(diff_result['ports']['closed'])} | "
                f"Neue CVEs: {len(diff_result['cves']['new'])} | "
                f"Behobene CVEs: {len(diff_result['cves']['resolved'])}"
            )
        except Exception as e:
            _log("OrchestratorAgent", f"Diff-Erstellung fehlgeschlagen (nicht kritisch): {e}")

    combined = (
        f"Ziel: {target}\n\n"
        f"=== RECON-OUTPUT ===\n{scan_output}\n\n"
        f"=== CVE-ANALYSE ===\n{cve_output}\n\n"
        f"=== REMEDIATION ===\n{remed_output}"
        f"{diff_section}"
    )

    try:
        summary_resp = client.messages.create(
            model=model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Erstelle die Management-Summary basierend auf diesen Ergebnissen:\n\n{combined}"
            }]
        )
        summary = next(
            (b.text for b in summary_resp.content if hasattr(b, "text")),
            "Management-Summary konnte nicht erstellt werden."
        )
    except Exception as e:
        summary = f"Management-Summary Fehler: {e}"

    # ── Schritt 5: Scan in Memory speichern ──────────────────────────────────
    try:
        new_scan_id = memory.save_scan(
            target          = target,
            ports           = [],   # werden in save_scan aus raw_scan geparst
            cves            = [],   # werden in save_scan aus raw_cves geparst
            raw_scan        = scan_output,
            raw_cves        = cve_output,
            raw_remediation = remed_output,
            summary         = summary
        )
        _log("OrchestratorAgent", f"Scan in Memory gespeichert (ID: {new_scan_id}).")

        # Diff ausgeben falls vorhanden
        if diff_result:
            _log("OrchestratorAgent", f"Vergleich: {diff_result['summary']}")
    except Exception as e:
        _log("OrchestratorAgent", f"Memory-Speichern fehlgeschlagen (nicht kritisch): {e}")

    _log("OrchestratorAgent", "Analyse vollständig abgeschlossen.")
    return summary


def stream_analysis(target: str) -> Iterator[dict]:
    """
    Generator für Live-Streaming in der GUI.
    Liefert Dicts: {'agent': str, 'content': str}
    """
    messages = []

    def log_cb(agent: str, msg: str):
        messages.append({"agent": agent, "content": msg})

    import threading

    result_holder = {"done": False, "error": None}

    def _run():
        try:
            run_full_analysis(target, log_callback=log_cb)
        except Exception as e:
            messages.append({"agent": "OrchestratorAgent", "content": f"FEHLER: {e}"})
        finally:
            result_holder["done"] = True

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    import time
    sent = 0
    while not result_holder["done"] or sent < len(messages):
        while sent < len(messages):
            yield messages[sent]
            sent += 1
        if not result_holder["done"]:
            time.sleep(0.05)

    thread.join(timeout=1)
