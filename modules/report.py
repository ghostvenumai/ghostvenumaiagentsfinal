# modules/report.py
import re
from datetime import datetime
import os

def _ensure_file(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

def _parse_ports(nmap_text: str):
    ports = []
    for line in nmap_text.splitlines():
        m = re.match(r"^\s*(\d+)\/(tcp|udp)\s+(\w+)\s+([^\s]+)(.*)$", line)
        if m:
            port, proto, state, service, rest = m.groups()
            ports.append({
                "port": int(port), "proto": proto, "state": state,
                "service": service, "extra": rest.strip()
            })
    return ports

def create_report(nmap_text: str, out_path: str = "report.txt"):
    """
    Nimmt Nmap-Text, extrahiert Portinfos und schreibt einen kompakten Report.
    """
    _ensure_file(out_path)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ports = _parse_ports(nmap_text or "")

    lines = []
    lines.append(f"GhostVenumAI Report — {ts}")
    lines.append("=" * 64)
    lines.append("")
    lines.append("Nmap Summary (erste 30 Zeilen):")
    lines.append("-" * 64)
    for l in (nmap_text or "").splitlines()[:30]:
        lines.append(l)
    lines.append("")
    lines.append("Erkannte offene Ports:")
    lines.append("-" * 64)
    if ports:
        for p in ports:
            lines.append(f"{p['port']}/{p['proto']}  {p['state']}  {p['service']}  {p['extra']}")
    else:
        lines.append("Keine Ports erkannt.")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
