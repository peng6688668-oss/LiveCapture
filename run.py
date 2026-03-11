#!/usr/bin/env python3
"""Live Capture — Eigenständige Anwendung für Echtzeit-Paketerfassung.

Basiert auf dem WiresharkPanel der Messtechnik Plattform.
"""

import sys
from pathlib import Path

from core.platform import setup_qt_platform

# Qt-Plattform initialisieren BEVOR QApplication erstellt wird
setup_qt_platform()

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QColor, QIcon, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QMainWindow, QMessageBox,
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

    def _open_pcap(self):
        """Öffnet eine PCAP/PCAPNG-Datei."""
        path, _ = QFileDialog.getOpenFileName(
            self, 'PCAP-Datei öffnen', '',
            'Capture-Dateien (*.pcap *.pcapng);;Alle Dateien (*)')
        if path:
            self._panel.load_pcap(path)

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
