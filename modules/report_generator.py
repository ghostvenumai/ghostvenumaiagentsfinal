# modules/report_generator.py
"""
ReportGenerator — Erstellt professionelle PDF-Berichte nach jedem Scan.

Enthält:
  - Executive Summary (verständlich ohne technisches Wissen)
  - CVE-Findings sortiert nach Schweregrad (Kritisch / Hoch / Mittel / Niedrig)
  - Pro Schwachstelle: Problem, betroffene Ports, Lösung
  - Metadaten: Datum, Client, Netzwerk, GhostVenumAI-Branding
  - Footer mit ghostvenumai.de

Abhängigkeit: reportlab  (pip install reportlab)
"""

import os
import re
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    _RL = True
except ImportError:
    _RL = False

# ── Farben ────────────────────────────────────────────────────────────────────
_C = {
    "dark":     HexColor("#1a1a2e") if _RL else None,
    "acc":      HexColor("#e94560") if _RL else None,
    "light":    HexColor("#f5f5f5") if _RL else None,
    "grey":     HexColor("#607080") if _RL else None,
    "critical": HexColor("#d32f2f") if _RL else None,
    "high":     HexColor("#f57c00") if _RL else None,
    "medium":   HexColor("#f9a825") if _RL else None,
    "low":      HexColor("#388e3c") if _RL else None,
    "white":    white              if _RL else None,
}

_SEV_COLOR = {
    "KRITISCH": _C["critical"],
    "HOCH":     _C["high"],
    "MITTEL":   _C["medium"],
    "NIEDRIG":  _C["low"],
    "CRITICAL": _C["critical"],
    "HIGH":     _C["high"],
    "MEDIUM":   _C["medium"],
    "LOW":      _C["low"],
}

_SEV_ORDER = {"KRITISCH": 0, "CRITICAL": 0,
              "HOCH": 1, "HIGH": 1,
              "MITTEL": 2, "MEDIUM": 2,
              "NIEDRIG": 3, "LOW": 3}


def _out_dir() -> Path:
    d = Path(__file__).parent.parent / "output"
    d.mkdir(exist_ok=True)
    return d


def _styles():
    base = getSampleStyleSheet()
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "title": ps("GVATitle",
            fontSize=22, leading=28, textColor=_C["dark"],
            fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=2),
        "sub": ps("GVASub",
            fontSize=10, textColor=_C["grey"],
            fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2),
        "h2": ps("GVAH2",
            fontSize=13, leading=17, textColor=_C["acc"],
            fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=6),
        "h3": ps("GVAH3",
            fontSize=11, leading=15, textColor=_C["dark"],
            fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4),
        "body": ps("GVABody",
            fontSize=10, leading=14, textColor=black,
            fontName="Helvetica", spaceAfter=4),
        "body_bold": ps("GVABodyBold",
            fontSize=10, leading=14, textColor=black,
            fontName="Helvetica-Bold", spaceAfter=2),
        "small": ps("GVASmall",
            fontSize=8, leading=11, textColor=_C["grey"],
            fontName="Helvetica-Oblique"),
        "footer": ps("GVAFooter",
            fontSize=8, textColor=_C["grey"],
            fontName="Helvetica", alignment=TA_CENTER),
        "code": ps("GVACode",
            fontSize=9, leading=12, textColor=_C["dark"],
            fontName="Courier", spaceAfter=4,
            backColor=_C["light"], leftIndent=8, rightIndent=8),
        "sev_label": ps("GVASev",
            fontSize=10, fontName="Helvetica-Bold",
            alignment=TA_CENTER),
    }


# ── CVE-Parser ────────────────────────────────────────────────────────────────

def _parse_cve_blocks(cve_text: str) -> list[dict]:
    """
    Parst strukturierte CVE-Blöcke aus dem VulnAgent-Output.
    Gibt Liste von Dicts: {cve_id, cvss, severity, service, port, description}
    """
    blocks = []
    seen   = set()

    # CVE-ID + CVSS Score
    pattern = re.compile(
        r"\[(?P<cve>CVE-\d{4}-\d+)\].*?CVSS[:\s]*(?P<score>[\d.]+)"
        r"(?:\s*\((?P<sev>[A-Za-zÄÖÜäöüß]+)\))?",
        re.IGNORECASE
    )
    for m in pattern.finditer(cve_text):
        cve_id = m.group("cve")
        if cve_id in seen:
            continue
        seen.add(cve_id)

        score = float(m.group("score"))
        sev   = m.group("sev") or ""
        if not sev:
            if score >= 9.0:   sev = "KRITISCH"
            elif score >= 7.0: sev = "HOCH"
            elif score >= 4.0: sev = "MITTEL"
            else:              sev = "NIEDRIG"
        sev = sev.upper()

        # Beschreibung: nächste ~250 Zeichen nach dem Match
        ctx_start = m.end()
        ctx = cve_text[ctx_start:ctx_start + 300].strip()
        # Alles bis zum nächsten CVE-Block
        next_cve = re.search(r"\[CVE-", ctx)
        desc = ctx[:next_cve.start()].strip() if next_cve else ctx

        # Service aus Kontext
        ctx_before = cve_text[max(0, m.start() - 200):m.start()]
        svc_m = re.search(
            r"(openssh|apache|nginx|vsftpd|samba|mysql|postgresql|"
            r"openssl|proftpd|postfix|dovecot|bind)",
            ctx_before, re.IGNORECASE
        )
        service = svc_m.group(1).lower() if svc_m else ""

        # Port aus Kontext
        port_m = re.search(r"(\d+)/(tcp|udp)", ctx_before)
        port   = port_m.group(0) if port_m else ""

        blocks.append({
            "cve_id":      cve_id,
            "cvss":        score,
            "severity":    sev,
            "service":     service,
            "port":        port,
            "description": desc[:250] if desc else "",
        })

    # Nach Schweregrad sortieren
    blocks.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 9))
    return blocks


# ── PDF-Generator ─────────────────────────────────────────────────────────────

def generate_report(
    target:          str,
    client_name:     str        = "",
    scan_output:     str        = "",
    cve_output:      str        = "",
    remediation:     str        = "",
    summary:         str        = "",
    doc_nr:          str        = "",
    out_path:        str        = "",
) -> str:
    """
    Erstellt den professionellen PDF-Sicherheitsbericht.

    Args:
        target:       Gescanntes Netzwerk / IP
        client_name:  Name des Kunden (optional)
        scan_output:  Roher Nmap-Output (ReconAgent)
        cve_output:   CVE-Analyse-Text (VulnAgent)
        remediation:  Fix-Empfehlungen (RemediationAgent)
        summary:      Management-Summary (OrchestratorAgent)
        doc_nr:       Dokumentnummer (optional, wird generiert)
        out_path:     Ausgabepfad (optional)

    Returns:
        Absoluter Pfad zur PDF-Datei.
    """
    if not _RL:
        raise ImportError(
            "reportlab nicht installiert. Bitte: pip install reportlab")

    now      = datetime.now()
    ts_label = now.strftime("%d.%m.%Y %H:%M:%S")
    ts_file  = now.strftime("%Y-%m-%d_%H%M%S")
    doc_nr   = doc_nr or f"GVA-{now.strftime('%Y%m%d-%H%M%S')}"

    if not out_path:
        safe_target = re.sub(r"[./\\]", "_", target)
        out_path = str(_out_dir() / f"report_{safe_target}_{ts_file}.pdf")

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=2.5*cm, rightMargin=2.5*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title=f"GhostVenumAI Security Report {doc_nr}",
        author="GhostVenumAI | ghostvenumai.de",
    )

    S = _styles()
    story = []

    # ── Deckblatt ─────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 1*cm),
        Paragraph("👻 GhostVenumAI", S["title"]),
        Paragraph("Security Analysis Report", S["sub"]),
        Spacer(1, 0.3*cm),
        HRFlowable(width="100%", thickness=2, color=_C["acc"]),
        Spacer(1, 0.5*cm),
    ]

    # Meta-Tabelle
    meta = [
        ["Dokument-Nr.:",  doc_nr],
        ["Ziel / Netzwerk:", target],
        ["Scan-Datum:",    ts_label],
    ]
    if client_name:
        meta.insert(1, ["Auftraggeber:", client_name])

    meta_tbl = Table(meta, colWidths=[4.5*cm, 11*cm], hAlign="LEFT")
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (-1,-1), "Helvetica"),
        ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [_C["light"], _C["white"]]),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("LEFTPADDING",    (0,0), (-1,-1), 8),
        ("GRID",           (0,0), (-1,-1), 0.5, _C["grey"]),
    ]))
    story += [meta_tbl, Spacer(1, 0.8*cm)]

    # ── Executive Summary ─────────────────────────────────────────────────────
    if summary:
        story.append(Paragraph("Executive Summary", S["h2"]))
        for line in summary.splitlines():
            if line.strip():
                story.append(Paragraph(line, S["body"]))
        story.append(Spacer(1, 0.5*cm))

    # ── CVE-Findings ──────────────────────────────────────────────────────────
    cve_blocks = _parse_cve_blocks(cve_output) if cve_output else []

    story.append(Paragraph(
        f"Gefundene Schwachstellen ({len(cve_blocks)})", S["h2"]))

    if not cve_blocks:
        story.append(Paragraph(
            "Keine CVEs mit bekannten CVSS-Scores gefunden.", S["body"]))
    else:
        # Schweregrad-Übersicht
        counts = {}
        for b in cve_blocks:
            counts[b["severity"]] = counts.get(b["severity"], 0) + 1

        overview_data = [["Schweregrad", "Anzahl"]]
        for sev in ["KRITISCH", "HOCH", "MITTEL", "NIEDRIG"]:
            if sev in counts:
                overview_data.append([sev, str(counts[sev])])

        ov_tbl = Table(overview_data, colWidths=[5*cm, 2.5*cm], hAlign="LEFT")
        ov_tbl.setStyle(TableStyle([
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
            ("BACKGROUND",  (0,0), (-1,0),  _C["dark"]),
            ("TEXTCOLOR",   (0,0), (-1,0),  _C["white"]),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [_C["light"], _C["white"]]),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.5, _C["grey"]),
        ]))
        story += [ov_tbl, Spacer(1, 0.5*cm)]

        # Einzelne CVE-Blöcke
        for b in cve_blocks:
            sev_color = _SEV_COLOR.get(b["severity"], _C["grey"])
            sev_bg    = HexColor("#fff3e0") if b["severity"] in ("HOCH","HIGH") \
                        else HexColor("#ffebee") if b["severity"] in ("KRITISCH","CRITICAL") \
                        else HexColor("#f9fbe7") if b["severity"] in ("NIEDRIG","LOW") \
                        else HexColor("#fffde7")

            header_row = [[
                Paragraph(b["severity"],
                    ParagraphStyle("S", fontSize=10, fontName="Helvetica-Bold",
                                   textColor=_C["white"])),
                Paragraph(
                    f"<b>{b['cve_id']}</b>  CVSS: {b['cvss']}"
                    + (f"  |  Service: {b['service']}" if b["service"] else "")
                    + (f"  |  Port: {b['port']}"       if b["port"]    else ""),
                    ParagraphStyle("H", fontSize=10, fontName="Helvetica",
                                   textColor=_C["dark"])),
            ]]
            h_tbl = Table(header_row, colWidths=[2.5*cm, 13*cm])
            h_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (0,0), sev_color),
                ("BACKGROUND",    (1,0), (1,0), sev_bg),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("GRID",          (0,0), (-1,-1), 0.5, _C["grey"]),
            ]))

            block_content = [h_tbl]
            if b["description"]:
                block_content.append(
                    Paragraph(b["description"],
                        ParagraphStyle("D", fontSize=9, fontName="Helvetica",
                                       textColor=_C["grey"], leftIndent=8,
                                       spaceAfter=0, spaceBefore=2)))
            block_content.append(Spacer(1, 0.3*cm))
            story.append(KeepTogether(block_content))

    # ── Remediation ───────────────────────────────────────────────────────────
    if remediation:
        story += [PageBreak(), Paragraph("Empfohlene Maßnahmen", S["h2"])]
        for line in remediation.splitlines():
            line = line.strip()
            if not line:
                story.append(Spacer(1, 0.15*cm))
            elif line.startswith("═") or line.startswith("─"):
                story.append(HRFlowable(
                    width="100%", thickness=0.5, color=_C["grey"]))
            elif any(line.startswith(p) for p in
                     ["[KRITISCH]","[HOCH]","[MITTEL]","[NIEDRIG]",
                      "[CRITICAL]","[HIGH]","[MEDIUM]","[LOW]"]):
                story.append(Paragraph(line, S["h3"]))
            elif line.startswith("sudo ") or line.startswith("apt ") \
                    or line.startswith("dnf ") or line.startswith("pacman "):
                story.append(Paragraph(line, S["code"]))
            else:
                story.append(Paragraph(line, S["body"]))

    # ── Nmap-Rohdaten (kompakt) ───────────────────────────────────────────────
    if scan_output:
        story += [PageBreak(), Paragraph("Nmap Scan-Rohdaten", S["h2"])]
        # Nur relevante Zeilen (offene Ports)
        relevant = [l for l in scan_output.splitlines()
                    if "open" in l.lower() or l.strip().startswith("Nmap")
                    or "Host:" in l or "PORT" in l]
        for line in relevant[:80]:   # max 80 Zeilen
            story.append(Paragraph(
                line, ParagraphStyle("R", fontSize=8, fontName="Courier",
                                     leading=11, textColor=_C["dark"],
                                     leftIndent=4)))

    # ── Footer ────────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 0.8*cm),
        HRFlowable(width="100%", thickness=0.5, color=_C["grey"]),
        Spacer(1, 0.2*cm),
        Paragraph(
            f"GhostVenumAI | ghostvenumai.de | "
            f"Dok.-Nr.: {doc_nr} | Erstellt: {ts_label}",
            S["footer"]),
    ]

    doc.build(story)
    return out_path


def check_reportlab() -> bool:
    return _RL
