#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Live Capture — 一键部署脚本
# 同步代码到远程 Linux 电脑，自动创建 venv 并安装依赖
# ═══════════════════════════════════════════════════════════════════

set -e

REMOTE_USER="localadm"
REMOTE_HOST="192.168.41.68"
REMOTE_DIR="~/LiveCapture"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "══════════════════════════════════════════════"
echo "  Live Capture — Deployment"
echo "══════════════════════════════════════════════"

# ── 1. 代码同步 ────────────────────────────────────────────
echo ""
echo "[1/3] Synchronisiere Code → ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"
rsync -avz --delete \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    "${LOCAL_DIR}/" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

# ── 2. Venv erstellen (nur beim ersten Mal) ────────────────
echo ""
echo "[2/3] Prüfe/erstelle virtuelle Umgebung auf Remote..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" bash -s <<'REMOTE_SCRIPT'
cd ~/LiveCapture

if [ ! -d "venv" ]; then
    echo "  → Erstelle venv..."
    python3 -m venv venv
    echo "  → venv erstellt"
else
    echo "  → venv existiert bereits"
fi
REMOTE_SCRIPT

# ── 3. Abhängigkeiten installieren ─────────────────────────
echo ""
echo "[3/3] Installiere/aktualisiere Abhängigkeiten..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" bash -s <<'REMOTE_SCRIPT'
cd ~/LiveCapture
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  → Abhängigkeiten OK"
REMOTE_SCRIPT

# ── Fertig ─────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  Deployment abgeschlossen!"
echo ""
echo "  Starten mit:"
echo "    ssh ${REMOTE_USER}@${REMOTE_HOST}"
echo "    cd LiveCapture && venv/bin/python run.py"
echo "══════════════════════════════════════════════"
