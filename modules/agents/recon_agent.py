# modules/agents/recon_agent.py
"""
ReconAgent — Entscheidet Scan-Strategie und führt Nmap-Scan durch.
Nutzt Claude (Anthropic SDK) mit nativem Tool-Calling.
"""
import os
import sys
import json
import subprocess
from typing import Any

try:
    import anthropic
except ImportError:
    raise ImportError("anthropic SDK nicht installiert. Bitte: pip install anthropic")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.scanner import run_nmap_scan

# ── Tool-Implementierungen ─────────────────────────────────────────────────────

def _ping_check(target: str) -> str:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            capture_output=True, text=True, timeout=5
        )
        return "erreichbar" if result.returncode == 0 else "nicht erreichbar"
    except Exception as e:
        return f"Ping-Fehler: {e}"

def _nmap_scan(target: str, nmap_args: str) -> str:
    return run_nmap_scan(target, nmap_args)

# ── Tool-Definitionen für Claude ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "ping_check",
        "description": "Prüft ob ein Host per ICMP erreichbar ist. Gibt 'erreichbar' oder 'nicht erreichbar' zurück.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Ziel-IP oder Hostname"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_scan",
        "description": (
            "Führt einen Nmap-Scan durch und gibt den vollständigen Output zurück. "
            "Nur für autorisierte Systeme verwenden."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target":    {"type": "string", "description": "Ziel-IP oder Netzwerk-Range"},
                "nmap_args": {"type": "string", "description": "Nmap-Parameter (z.B. '-sS -sV -T4 -O')"}
            },
            "required": ["target", "nmap_args"]
        }
    }
]

SYSTEM_PROMPT = """Du bist ReconAgent — ein defensiver Netzwerk-Reconnaissance-Agent für GhostVenumAI.

Dein Workflow:
1. Prüfe zuerst mit ping_check ob der Host/das Netz erreichbar ist.
2. Wähle die Nmap-Strategie:
   - Einzelner Host (x.x.x.x)    → '-sS -sV -T4 -O'
   - Netzwerk-Range (x.x.x.x/24) → erst '-sn -T4' (Discovery), dann '-sV -T4' auf gefundene Hosts
   - Wenn Port 80/443 offen       → füge '--script=http-headers,http-title' hinzu
3. Führe den Scan aus.
4. Gib eine strukturierte Zusammenfassung zurück:
   - Online-Hosts
   - Offene Ports und Dienste mit Versionen

WICHTIG: Scanne NUR Systeme mit expliziter Erlaubnis. Kein Exploit-Code, kein Brute-Force."""

# ── Agent-Ausführung ───────────────────────────────────────────────────────────

def _execute_tool(name: str, inputs: dict) -> str:
    if name == "ping_check":
        return _ping_check(inputs["target"])
    if name == "nmap_scan":
        return _nmap_scan(inputs["target"], inputs.get("nmap_args", "-sS -sV -T4"))
    return f"Unbekanntes Tool: {name}"

def run(target: str, client: anthropic.Anthropic, model: str = "claude-sonnet-4-6") -> str:
    """Führt den ReconAgent aus und gibt den vollständigen Scan-Output zurück."""
    messages = [{"role": "user", "content": f"Analysiere dieses Ziel: {target}"}]

    while True:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages
        )

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = _execute_tool(block.name, block.input)
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     result
                    })
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user",      "content": tool_results})

        else:  # end_turn
            return next(
                (b.text for b in response.content if hasattr(b, "text")),
                "Kein Output vom ReconAgent."
            )
