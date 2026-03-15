# modules/gpt_analysis.py
import os
import json
from datetime import datetime

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

LOG_DIR = "logs"

def _ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)

def _load_openai_key():
    # Priorität: Env-Var > config.json
    key = os.getenv("OPENAI_API_KEY") or os.getenv("GVA_OPENAI_KEY")
    if key:
        return key
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("openai_key") or cfg.get("OPENAI_API_KEY")
    except Exception:
        return None

def analyze_scan_with_gpt(nmap_output: str, model: str = "gpt-4o-mini") -> str:
    """
    Defensiv: Nimmt Nmap-Output, analysiert Schwachstellen und empfiehlt Schutzmaßnahmen.
    Gibt den Pfad zur gespeicherten Analyse zurück.
    """
    _ensure_dirs()

    api_key = _load_openai_key()
    if not api_key:
        raise RuntimeError("Kein OpenAI API-Key gefunden (Env: OPENAI_API_KEY oder config.json: openai_key).")

    if OpenAI is None:
        raise RuntimeError("OpenAI SDK nicht installiert. Bitte: pip install openai>=1.0.0")

    client = OpenAI(api_key=api_key)

    system_prompt = (
        "Du bist ein defensiver Netzwerk-Sicherheitsanalyst. "
        "Analysiere den folgenden Nmap-Scan und erstelle einen strukturierten Sicherheitsbericht:\n"
        "1) Zusammenfassung: Ziel, Scan-Zeitpunkt, gefundene Hosts\n"
        "2) Offene Ports und Dienste (tabellarisch)\n"
        "3) Identifizierte Schwachstellen und Risikobewertung (Low/Medium/High/Critical)\n"
        "4) Empfohlene Schutzmaßnahmen und Updates\n"
        "5) Prioritätsliste: Was zuerst beheben?\n\n"
        "Fokus: Defensiv, konkrete Schutzmaßnahmen, keine Exploit-Empfehlungen."
    )

    resp = client.chat.completions.create(
        model=model,
        temperature=0.2,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": nmap_output},
        ],
    )

    content = resp.choices[0].message.content
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_path = os.path.join(LOG_DIR, f"gpt_analysis_{ts}.txt")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    return out_path
