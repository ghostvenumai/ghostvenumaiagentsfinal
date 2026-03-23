#!/bin/bash
# GhostVenumAI — HTTPS Setup Script
# Richtet nginx + Self-Signed SSL ein
# Ausführen mit: sudo bash setup_https.sh

set -e
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   GhostVenumAI — HTTPS Setup                 ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 1. nginx installieren ──────────────────────────────────────
echo "[1/5] Installiere nginx..."
apt-get install -y nginx > /dev/null 2>&1
echo "      ✓ nginx installiert"

# ── 2. SSL-Zertifikat erstellen ────────────────────────────────
echo "[2/5] Erstelle Self-Signed SSL-Zertifikat (RSA 4096, 2 Jahre)..."
mkdir -p /etc/ssl/ghostvenum

openssl req -x509 -nodes -days 730 \
  -newkey rsa:4096 \
  -keyout /etc/ssl/ghostvenum/ghostvenum.key \
  -out    /etc/ssl/ghostvenum/ghostvenum.crt \
  -subj   "/C=DE/ST=Deutschland/L=Lokal/O=GhostVenumAI/OU=Security/CN=ghostvenum.local" \
  -addext "subjectAltName=IP:127.0.0.1,IP:192.168.178.1,DNS:localhost,DNS:ghostvenum.local" \
  2>/dev/null

chmod 600 /etc/ssl/ghostvenum/ghostvenum.key
chmod 644 /etc/ssl/ghostvenum/ghostvenum.crt
echo "      ✓ Zertifikat erstellt (/etc/ssl/ghostvenum/)"

# ── 3. nginx konfigurieren ─────────────────────────────────────
echo "[3/5] Konfiguriere nginx..."
cp "$SCRIPT_DIR/nginx_ghostvenum.conf" /etc/nginx/sites-available/ghostvenum

# Default-Seite deaktivieren
rm -f /etc/nginx/sites-enabled/default

# GhostVenum aktivieren
ln -sf /etc/nginx/sites-available/ghostvenum /etc/nginx/sites-enabled/ghostvenum

# Konfiguration prüfen
nginx -t
echo "      ✓ nginx konfiguriert"

# ── 4. nginx starten/neu laden ────────────────────────────────
echo "[4/5] Starte nginx..."
systemctl enable nginx
systemctl restart nginx
echo "      ✓ nginx läuft"

# ── 5. UFW Firewall anpassen ──────────────────────────────────
echo "[5/5] Öffne Port 443 (HTTPS) in UFW..."
ufw allow 443/tcp comment 'HTTPS GhostVenumAI' 2>/dev/null || true
ufw deny 5000/tcp comment 'Flask direkt sperren' 2>/dev/null || true
echo "      ✓ Firewall angepasst"

# ── Zusammenfassung ────────────────────────────────────────────
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║          HTTPS Setup abgeschlossen!          ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  ✓ nginx als Reverse Proxy aktiv             ║"
echo "║  ✓ Self-Signed SSL (RSA 4096, 2 Jahre)       ║"
echo "║  ✓ TLS 1.2 + 1.3 (BSI TR-02102)             ║"
echo "║  ✓ Port 80 → 443 Weiterleitung               ║"
echo "║  ✓ Zugriff nur aus Heimnetz (192.168.x.x)    ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  HTTPS URL: https://$LOCAL_IP"
echo "║  (Browser zeigt Zertifikatswarnung — normal  ║"
echo "║   bei Self-Signed. Ausnahme hinzufügen.)     ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Tipp: Flask muss weiterhin laufen (Port 5000 intern)"
echo "      nginx leitet HTTPS → Flask weiter"
echo ""
