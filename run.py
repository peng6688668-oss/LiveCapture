#!/usr/bin/env python3
"""Live Capture — Eigenständige Anwendung für Echtzeit-Paketerfassung.

Basiert auf dem WiresharkPanel der Messtechnik Plattform.
"""

import sys
from pathlib import Path

from core.platform import setup_qt_platform

# Qt-Plattform initialisieren BEVOR QApplication erstellt wird
setup_qt_platform()

# WebEngine MUSS vor QApplication importiert werden (Qt-Requirement)
# Chromium verlangt --no-sandbox wenn als root (sudo) gestartet
import os
if os.geteuid() == 0:
    os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--no-sandbox'

# Mesa llvmpipe Software-Renderer: Thread-Anzahl begrenzen
# Ohne GPU erstellt Mesa 12+ Threads die ~120% CPU verbrauchen
# und USB-Interrupt-Verarbeitung blockieren (→ V4L2 select timeout)
os.environ.setdefault('LP_NUM_THREADS', '2')
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView  # noqa: F401
except ImportError:
    pass

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QLabel, QMainWindow, QMessageBox, QWidget,
)


class LiveCaptureWindow(QMainWindow):
    """Hauptfenster für die Live-Capture-Anwendung."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Live Capture — Netzwerkanalyse')

        # ── Central Widget ──────────────────────────────────────────
        from ui.wireshark_panel import WiresharkPanel
        self._panel = WiresharkPanel(self, live_capture_mode=True)
        self.setCentralWidget(self._panel)

        # ── Menüleiste ──────────────────────────────────────────────
        self._setup_menubar()

    def _setup_menubar(self):
        """Erstellt die Menüleiste."""
        menubar = self.menuBar()

        # ── Datei ───────────────────────────────────────────────────
        file_menu = menubar.addMenu('&Datei')

        open_action = QAction('PCAP &öffnen…', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self._open_pcap)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        quit_action = QAction('&Beenden', self)
        quit_action.setShortcut('Ctrl+Q')
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # ── Hilfe ───────────────────────────────────────────────────
        help_menu = menubar.addMenu('&Hilfe')

        about_action = QAction('Ü&ber…', self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

        # ── System-Monitor (rechts in der Menüleiste) ──────────────
        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().Policy.Expanding,
                             spacer.sizePolicy().Policy.Preferred)
        menubar.setCornerWidget(self._create_system_monitor(), Qt.Corner.TopRightCorner)

    def _open_pcap(self):
        """Öffnet eine PCAP/PCAPNG-Datei."""
        path, _ = QFileDialog.getOpenFileName(
            self, 'PCAP-Datei öffnen', '',
            'Capture-Dateien (*.pcap *.pcapng);;Alle Dateien (*)')
        if path:
            self._panel.load_pcap(path)

    def _create_system_monitor(self) -> QWidget:
        """Erstellt das System-Monitor Widget fuer die Menüleiste."""
        from PyQt6.QtWidgets import QHBoxLayout
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(12)

        mono = QFont("Consolas", 8)

        self._cpu_label = QLabel("CPU: ---%")
        self._cpu_label.setFont(mono)
        self._cpu_label.setStyleSheet("color: #1565c0;")
        layout.addWidget(self._cpu_label)

        self._ram_label = QLabel("RAM: ---MB")
        self._ram_label.setFont(mono)
        self._ram_label.setStyleSheet("color: #2e7d32;")
        layout.addWidget(self._ram_label)

        self._top_proc_label = QLabel("")
        self._top_proc_label.setFont(QFont("Consolas", 7))
        self._top_proc_label.setStyleSheet("color: #888;")
        layout.addWidget(self._top_proc_label)

        # Vorherige CPU-Werte fuer Delta-Berechnung
        self._prev_cpu_times = None

        # Timer: alle 2 Sekunden aktualisieren
        self._sysmon_timer = QTimer(self)
        self._sysmon_timer.timeout.connect(self._update_system_monitor)
        self._sysmon_timer.start(2000)
        # Sofort einmal ausfuehren
        QTimer.singleShot(500, self._update_system_monitor)

        return widget

    def _update_system_monitor(self):
        """Liest CPU/RAM aus /proc und aktualisiert die Anzeige."""
        try:
            # ── CPU-Auslastung (Delta seit letztem Aufruf) ──
            with open('/proc/stat') as f:
                parts = f.readline().split()
            # user, nice, system, idle, iowait, irq, softirq, steal
            times = [int(x) for x in parts[1:9]]
            total = sum(times)
            idle = times[3] + times[4]  # idle + iowait

            if self._prev_cpu_times is not None:
                prev_total, prev_idle = self._prev_cpu_times
                d_total = total - prev_total
                d_idle = idle - prev_idle
                cpu_pct = 100.0 * (1.0 - d_idle / max(d_total, 1))
            else:
                cpu_pct = 0.0
            self._prev_cpu_times = (total, idle)

            # Farbe nach Auslastung
            if cpu_pct > 80:
                cpu_color = "#d32f2f"  # Rot
            elif cpu_pct > 50:
                cpu_color = "#f57c00"  # Orange
            else:
                cpu_color = "#1565c0"  # Blau
            self._cpu_label.setText(f"CPU: {cpu_pct:.0f}%")
            self._cpu_label.setStyleSheet(f"color: {cpu_color};")

            # ── RAM-Auslastung ──
            mem_info = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    key, val = line.split(':')
                    mem_info[key.strip()] = int(val.split()[0])  # kB
            total_mb = mem_info.get('MemTotal', 0) / 1024
            avail_mb = mem_info.get('MemAvailable', 0) / 1024
            used_mb = total_mb - avail_mb
            ram_pct = 100.0 * used_mb / max(total_mb, 1)

            if ram_pct > 85:
                ram_color = "#d32f2f"
            elif ram_pct > 60:
                ram_color = "#f57c00"
            else:
                ram_color = "#2e7d32"
            self._ram_label.setText(
                f"RAM: {used_mb:.0f}/{total_mb:.0f}MB ({ram_pct:.0f}%)")
            self._ram_label.setStyleSheet(f"color: {ram_color};")

            # ── Top-Prozess (hoechster CPU-Verbrauch) ──
            top_name = ""
            top_cpu = 0.0
            try:
                import subprocess
                result = subprocess.run(
                    ['ps', '-eo', 'comm,%cpu', '--sort=-%cpu', '--no-headers'],
                    capture_output=True, text=True, timeout=2)
                for line in result.stdout.strip().split('\n')[:1]:
                    parts = line.rsplit(None, 1)
                    if len(parts) == 2:
                        top_name = parts[0].strip()[:15]
                        top_cpu = float(parts[1])
            except Exception:
                pass
            if top_name:
                self._top_proc_label.setText(
                    f"Top: {top_name} {top_cpu:.0f}%")
            else:
                self._top_proc_label.setText("")

        except Exception:
            pass

    def _show_about(self):
        """Zeigt den Über-Dialog."""
        QMessageBox.about(
            self, 'Über Live Capture',
            '<h3>Live Capture</h3>'
            '<p>Eigenständige Anwendung für Echtzeit-Netzwerkanalyse.</p>'
            '<p>Basiert auf der Messtechnik Plattform.</p>'
            '<p>© ViGEM GmbH</p>')


def main():
    """Einstiegspunkt der Anwendung."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName('live-capture')
    app.setApplicationDisplayName('Live Capture')
    app.setOrganizationName('ViGEM')

    # ── Icon (weiß → transparent) ───────────────────────────────
    icon_path = Path(__file__).parent / 'resources' / 'vigem.png'
    if icon_path.exists():
        app_icon = QIcon()
        for sz in (16, 32, 48):
            img = QImage(str(icon_path))
            img = img.scaled(sz, sz,
                             Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
            img = img.convertToFormat(QImage.Format.Format_ARGB32)
            for y in range(img.height()):
                for x in range(img.width()):
                    c = img.pixelColor(x, y)
                    if c.red() > 240 and c.green() > 240 and c.blue() > 240:
                        img.setPixelColor(x, y, QColor(0, 0, 0, 0))
            app_icon.addPixmap(QPixmap.fromImage(img))
        app.setWindowIcon(app_icon)

    # ── Theme ───────────────────────────────────────────────────
    from ui.theme import ThemeManager
    theme_mgr = ThemeManager.instance()
    theme_mgr.apply_theme(app, 'light')

    # ── Hauptfenster ────────────────────────────────────────────
    window = LiveCaptureWindow()
    window.showMaximized()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
