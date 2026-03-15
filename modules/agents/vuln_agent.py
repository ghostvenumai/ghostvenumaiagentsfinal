# modules/agents/vuln_agent.py
"""
VulnAgent — Parst Scan-Output und sucht CVEs in der NVD-Datenbank.
Nutzt Claude (Anthropic SDK) mit nativem Tool-Calling.
"""
import re
import requests

try:
    import anthropic
except ImportError:
    raise ImportError("anthropic SDK nicht installiert. Bitte: pip install anthropic")

# ── Tool-Implementierungen ─────────────────────────────────────────────────────

def _parse_services(scan_output: str) -> str:
    services = []
    for line in scan_output.splitlines():
        m = re.search(r"(\d+/(?:tcp|udp))\s+open\s+\S+\s+(.*)", line)
        if m:
            port_proto = m.group(1)
            version_str = m.group(2).strip()
            if version_str:
                services.append(f"{port_proto}  {version_str}")
    return "\n".join(services) if services else "Keine offenen Services mit Versionsinformation gefunden."

def _lookup_cve(service_name: str, version: str = "") -> str:
    query  = f"{service_name} {version}".strip()
    url    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 5}
    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return f"Keine CVEs gefunden für: {query}"
        results = []
        for v in vulns:
            cve    = v["cve"]
            cve_id = cve["id"]
            desc   = cve["descriptions"][0]["value"][:250] if cve.get("descriptions") else ""
            score  = "N/A"
            sev    = ""
            m_ = cve.get("metrics", {})
            if "cvssMetricV31" in m_:
                d     = m_["cvssMetricV31"][0]["cvssData"]
                score = d["baseScore"]
                sev   = d.get("baseSeverity", "")
            elif "cvssMetricV2" in m_:
                d     = m_["cvssMetricV2"][0]["cvssData"]
                score = d["baseScore"]
                sev   = m_["cvssMetricV2"][0].get("baseSeverity", "")
            results.append(f"[{cve_id}] CVSS: {score} ({sev})\n{desc}")
        return "\n\n".join(results)
    except requests.exceptions.Timeout:
        return "CVE-Lookup Timeout — NVD API nicht erreichbar."
    except Exception as e:
        return f"CVE-Lookup Fehler: {e}"

# ── Tool-Definitionen für Claude ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "parse_services_from_scan",
        "description": "Extrahiert Service-Namen und Versionen aus Nmap-Output. Gibt eine Liste zurück.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_output": {"type": "string", "description": "Vollständiger Nmap-Output"}
            },
            "required": ["scan_output"]
        }
    },
    {
        "name": "lookup_cve",
        "description": (
            "Sucht bekannte CVEs für einen Service in der NVD-Datenbank (NIST). "
            "Kostenlos, kein API-Key erforderlich."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string", "description": "Name des Dienstes (z.B. 'openssh', 'apache')"},
                "version":      {"type": "string", "description": "Version des Dienstes (z.B. '8.9p1', '2.4.51')"}
            },
            "required": ["service_name"]
        }
    }
]

SYSTEM_PROMPT = """Du bist VulnAgent — ein Schwachstellen-Analyse-Agent für GhostVenumAI.

Workflow:
1. Extrahiere alle Services mit parse_services_from_scan.
2. Suche für jeden Service CVEs mit lookup_cve (Service-Name + Version).
3. Priorisiere nach CVSS-Score:
   - Kritisch: >= 9.0 | Hoch: 7.0-8.9 | Mittel: 4.0-6.9 | Niedrig: < 4.0
4. Strukturierte Ausgabe:
   - Service + Version
   - CVE-ID + CVSS + Schweregrad
   - Kurzbeschreibung

Fokus auf Score >= 7.0. Generiere KEINEN Exploit-Code."""

# ── Agent-Ausführung ───────────────────────────────────────────────────────────

def _execute_tool(name: str, inputs: dict) -> str:
    if name == "parse_services_from_scan":
        return _parse_services(inputs["scan_output"])
    if name == "lookup_cve":
        return _lookup_cve(inputs["service_name"], inputs.get("version", ""))
    return f"Unbekanntes Tool: {name}"

def run(scan_output: str, client: anthropic.Anthropic, model: str = "claude-sonnet-4-6") -> str:
    """Führt den VulnAgent aus und gibt die CVE-Analyse zurück."""
    messages = [{"role": "user", "content": f"Analysiere diesen Nmap-Scan auf Schwachstellen:\n\n{scan_output}"}]

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

        else:
            return next(
                (b.text for b in response.content if hasattr(b, "text")),
                "Kein Output vom VulnAgent."
            )
