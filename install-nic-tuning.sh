#!/bin/bash
# Installiert den NIC-Tuning systemd Service
# Einmalig ausfuehren nach dem Kopieren auf einen neuen Rechner:
#   sudo bash install-nic-tuning.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${SCRIPT_DIR}/nic-tuning.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Bitte mit sudo ausfuehren: sudo bash $0"
    exit 1
fi

# Skript kopieren
cp "$SRC" /usr/local/bin/nic-tuning.sh
chmod +x /usr/local/bin/nic-tuning.sh

# systemd Service erstellen
cat > /etc/systemd/system/nic-tuning.service << 'SVC'
[Unit]
Description=NIC Performance Tuning (IRQ Affinity + Coalesce + Ring Buffer + RPS)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nic-tuning.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable nic-tuning.service
systemctl start nic-tuning.service

echo ""
echo "NIC-Tuning Service installiert und gestartet."
echo "  Status:   systemctl status nic-tuning.service"
echo "  Neustart: sudo systemctl restart nic-tuning.service"
echo "  Log:      journalctl -u nic-tuning.service"
