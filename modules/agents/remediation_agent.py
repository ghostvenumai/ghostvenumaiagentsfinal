# modules/agents/remediation_agent.py
"""
RemediationAgent — Generiert Fix-Empfehlungen für gefundene CVEs.
Nutzt Claude (Anthropic SDK) mit nativem Tool-Calling.
"""
import os
import sys
from pathlib import Path
from datetime import datetime

try:
    import anthropic
except ImportError:
    raise ImportError("anthropic SDK nicht installiert. Bitte: pip install anthropic")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ── Tool-Implementierungen ─────────────────────────────────────────────────────

_FIX_DB = {
    "openssh": {
        "debian":  "sudo apt update && sudo apt upgrade -y openssh-server",
        "rhel":    "sudo dnf update -y openssh-server",
        "arch":    "sudo pacman -Syu openssh",
        "windows": "Lade aktuelle OpenSSH-Version von github.com/PowerShell/Win32-OpenSSH",
    },
    "apache": {
        "debian":  "sudo apt update && sudo apt upgrade -y apache2",
        "rhel":    "sudo dnf update -y httpd",
        "arch":    "sudo pacman -Syu apache",
        "windows": "Lade Apache von apachelounge.com",
    },
    "nginx": {
        "debian":  "sudo apt update && sudo apt upgrade -y nginx",
        "rhel":    "sudo dnf update -y nginx",
        "arch":    "sudo pacman -Syu nginx",
        "windows": "Lade nginx von nginx.org/en/download.html",
    },
    "mysql":      {"debian": "sudo apt update && sudo apt upgrade -y mysql-server",  "rhel": "sudo dnf update -y mysql-server"},
    "postgresql": {"debian": "sudo apt update && sudo apt upgrade -y postgresql",    "rhel": "sudo dnf update -y postgresql-server"},
    "vsftpd":     {"debian": "sudo apt update && sudo apt upgrade -y vsftpd",        "rhel": "sudo dnf update -y vsftpd"},
    "samba":      {"debian": "sudo apt update && sudo apt upgrade -y samba",         "rhel": "sudo dnf update -y samba"},
}
_ALIAS = {
    "httpd": "apache", "apache2": "apache", "http": "apache",
    "mariadb": "mysql", "postgres": "postgresql",
    "ssh": "openssh", "smb": "samba", "ftp": "vsftpd",
}

def _generate_fix(service: str, os_type: str = "debian") -> str:
    key  = _ALIAS.get(service.lower().split()[0], service.lower().split()[0])
    db   = _FIX_DB.get(key, {})
    if not db:
        return (
            f"Kein spezifischer Befehl für '{service}'.\n"
            f"Allgemein (Debian): sudo apt update && sudo apt upgrade\n"
            f"Allgemein (RHEL):   sudo dnf update"
        )
    cmd = db.get(os_type.lower())
    if cmd:
        return cmd
    lines = [f"OS '{os_type}' nicht spezifisch — verfügbare Befehle:"]
    for k, v in db.items():
        lines.append(f"  [{k}] {v}")
    return "\n".join(lines)

def _save_report(content: str) -> str:
    out_dir = Path(_ROOT) / "output"
    out_dir.mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"remediation_{ts}.txt"
    path.write_text(content, encoding="utf-8")
    return str(path)

# ── Tool-Definitionen für Claude ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "generate_fix_commands",
        "description": "Generiert Update-Befehle für einen verwundbaren Service.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Name des Dienstes (z.B. 'openssh', 'apache')"},
                "os_type": {"type": "string", "description": "Betriebssystem: 'debian', 'rhel', 'arch', 'windows'"}
            },
            "required": ["service"]
        }
    },
    {
        "name": "save_remediation_report",
        "description": "Speichert den Remediation-Bericht als Datei im output/-Verzeichnis. Gibt den Dateipfad zurück.",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Vollständiger Berichtsinhalt"}
            },
            "required": ["content"]
        }
    }
]

SYSTEM_PROMPT = """Du bist RemediationAgent — ein Security-Remediation-Agent für GhostVenumAI.

Für jede Schwachstelle:
1. Erkläre das Risiko (1-2 Sätze, verständlich für Admins)
2. Hole Update-Befehle mit generate_fix_commands
3. Gib Workarounds falls kein Patch verfügbar
4. Weise Priorität zu

Format pro Finding:
═══════════════════════════════════════════════
[SCHWEREGRAD] Service: <name> — Port <port>
CVE: <CVE-ID> | CVSS: <score>
Risiko: <Erklärung>
Fix:    <Befehl>
Workaround: <falls vorhanden, sonst 'Keiner bekannt'>
Priorität: SOFORT / DIESE WOCHE / OPTIONAL
═══════════════════════════════════════════════

Schweregrade: KRITISCH (>=9) | HOCH (7-8.9) | MITTEL (4-6.9) | NIEDRIG (<4)
Prioritäten:  SOFORT (>=9)   | DIESE WOCHE (7-8.9)            | OPTIONAL (<7)

Am Ende: Management-Summary + Bericht speichern mit save_remediation_report.
Generiere KEINEN Exploit-Code."""

# ── Agent-Ausführung ───────────────────────────────────────────────────────────

def _execute_tool(name: str, inputs: dict) -> str:
    if name == "generate_fix_commands":
        return _generate_fix(inputs["service"], inputs.get("os_type", "debian"))
    if name == "save_remediation_report":
        return _save_report(inputs["content"])
    return f"Unbekanntes Tool: {name}"

def run(cve_findings: str, client: anthropic.Anthropic, model: str = "claude-sonnet-4-6") -> str:
    """Führt den RemediationAgent aus und gibt die Fix-Empfehlungen zurück."""
    messages = [{"role": "user", "content": f"Erstelle Fix-Empfehlungen für diese CVE-Findings:\n\n{cve_findings}"}]

    while True:
        response = client.messages.create(
            model=model,
            max_tokens=8192,
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

        else:
            return next(
                (b.text for b in response.content if hasattr(b, "text")),
                "Kein Output vom RemediationAgent."
            )
