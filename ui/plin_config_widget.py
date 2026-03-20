"""PCAN-USB Pro FD (LIN) Konfiguration und TX/RX-Ansicht fuer Live LIN.

Integriert sich in die bestehende Live LIN Seite des WiresharkPanels:
- Faltbares Konfigurationspanel (Schnittstelle, Bitrate, Master/Slave, Pruefsumme)
- TX-Bereich: Sende-Konfiguration + Sende-Historie
- Bestehendes LIN-TableView als RX-Bereich (mit BusTableModel + FilterHeader)
- Empfangene PLIN-Frames werden in bus_queues eingespeist
"""

import glob
import logging
import os
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QCheckBox, QHeaderView,
    QGroupBox, QMessageBox, QTableView, QFileDialog, QInputDialog,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QFileSystemWatcher
from PyQt6.QtGui import QColor, QFont

from ui.widgets.native_combo_box import NativeComboBox, NATIVE_COMBO_CSS

try:
    import cantools
    CANTOOLS_AVAILABLE = True
except ImportError:
    CANTOOLS_AVAILABLE = False

_log = logging.getLogger(__name__)

# ── plin-linux ─────────────────────────────────────────────────────────
try:
    from plin.device import PLIN
    from plin.enums import PLINMode, PLINFrameDirection, PLINFrameChecksumType
    from plin.structs import PLINMessage
    PLIN_AVAILABLE = True
except ImportError:
    PLIN_AVAILABLE = False

# ── Konstanten ─────────────────────────────────────────────────────────
_BAUDRATES = ["2400", "4800", "9600", "19200"]
_TX_HEADERS = ["Nr.", "Zeit", "Kanal", "ID", "Name", "DLC", "Daten", "Prüfsumme"]

_MONO = QFont("Consolas", 9)
_MONO_BOLD = QFont("Consolas", 9, QFont.Weight.Bold)
_DIFF_FG = QColor(220, 50, 50)
_MAX_TX_ROWS = 5000

# ── Spezial-Styles (nur fuer besondere Zustaende) ────────────────────
_BTN_CONNECT_CHECKED = (
    "QPushButton:checked { background: #2E7D32; color: white; font-weight: bold; }"
)
_TX_ROW_BG = QColor(200, 220, 255)  # Helles Blau fuer TX-Zeilen


# ── Hilfsfunktionen ───────────────────────────────────────────────────

def get_lin_interfaces():
    """Gibt Liste der verfuegbaren /dev/plin* Geraete zurueck."""
    devs = sorted(glob.glob('/dev/plin*'))
    return devs if devs else ['/dev/plin0']


def _calc_checksum(data: bytes, pid: int = None, enhanced: bool = True) -> int:
    """Berechnet LIN-Pruefsumme (Classic oder Enhanced).

    Enhanced (LIN 2.x): PID + Datenbytes
    Classic  (LIN 1.3): nur Datenbytes
    """
    s = pid if (enhanced and pid is not None) else 0
    for b in data:
        s += b
        if s >= 256:
            s -= 255
    return (~s) & 0xFF


# ═══════════════════════════════════════════════════════════════════════════
# LIN-Empfangsthread
# ═══════════════════════════════════════════════════════════════════════════

class LinReceiveThread(QThread):
    """Empfaengt LIN-Nachrichten ueber plin-linux in einem Worker-Thread."""

    frame_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, plin_dev, parent=None):
        super().__init__(parent)
        self._plin = plin_dev
        self._running = True

    def run(self):
        while self._running:
            try:
                frame = self._plin.read(block=False)
                if frame is not None:
                    data = bytes(frame.data[:frame.len])
                    self.frame_received.emit({
                        'timestamp': time.time(),
                        'channel': '',
                        'lin_id': frame.id & 0x3F,
                        'pid': frame.id,
                        'dlc': frame.len,
                        'data': data,
                        'direction': frame.dir,
                        'checksum': None,
                    })
                else:
                    self.msleep(10)
            except Exception as e:
                if self._running:
                    self.error_occurred.emit(str(e))
                break

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# PlinLinPage — Wrapper fuer die LIN-Seite
# ═══════════════════════════════════════════════════════════════════════════

class PlinLinPage(QWidget):
    """Wrapper fuer die LIN-Seite mit PCAN-USB Pro FD (LIN) Integration.

    Nimmt das bestehende LIN-TableView (BusTableModel) als RX-Bereich
    und fuegt PLIN-Konfiguration + TX-Bereich darueber.
    """

    # Signal: formatiertes Row-Tuple fuer bus_queues
    # Format: (zeit, kanal, lin_id, name, dlc, data_hex, pruefsumme)
    frame_for_bus_queue = pyqtSignal(tuple)

    def __init__(self, existing_lin_table: QTableView, parent=None):
        super().__init__(parent)
        self._existing_table = existing_lin_table
        self._plin: Optional[object] = None
        self._rx_thread: Optional[LinReceiveThread] = None
        self._tx_count = 0
        self._rx_count = 0
        self._start_time: Optional[float] = None
        self._periodic_timer: Optional[QTimer] = None
        self._periodic_count = 0
        self._ldf = None  # cantools Database (LDF)
        self._ldf_name = ''
        self._tx_reference: Dict[int, bytes] = {}
        self._last_tx_count = 0
        self._last_rx_count = 0
        self._bus_row_counters = None
        self._bus_index = 1
        self._last_bus_row_count = 0
        self._stats_widget = None  # BusStatisticsWidget
        self._id_stats: Dict[int, dict] = {}  # Per-ID Statistik
        self._id_stats_widget = None  # LinIdStatsWidget
        self._init_ui()
        self._init_device_watcher()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Faltbares Konfigurationspanel ───────────────────────────
        self._config_widget = self._create_config_panel()
        layout.addWidget(self._config_widget)

        # ── TX/RX Splitter ──────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #d0d0d8; height: 3px; }")

        # TX-Bereich
        splitter.addWidget(self._create_tx_section())

        # RX-Bereich: bestehendes LIN-TableView
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        rx_header_widget = QWidget()
        rx_header_widget.setFixedHeight(22)
        rx_header_widget.setStyleSheet(
            "background-color: #2E7D32; color: white;")
        rx_header_layout = QHBoxLayout(rx_header_widget)
        rx_header_layout.setContentsMargins(4, 0, 4, 0)
        rx_header_layout.setSpacing(8)

        self._rx_title = QLabel("RX \u2014 Empfangene Daten (TECMP + PLIN)")
        rx_title = self._rx_title
        rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(rx_title)
        rx_header_layout.addStretch()

        self._rx_rate_label = QLabel("0 paket/s")
        self._rx_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)
        splitter.addWidget(rx_wrapper)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        # ── Raten-Timer (1x pro Sekunde) ──
        self._rate_timer = QTimer(self)
        self._rate_timer.setInterval(1000)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start()
        self._auto_load_ldf()

    # ── Geraete-Hotplug-Ueberwachung ────────────────────────────────────

    def _init_device_watcher(self):
        """Ueberwacht /dev/ auf Aenderungen an plin*-Geraeten."""
        self._dev_watcher = QFileSystemWatcher(['/dev/'], self)
        self._dev_watcher.directoryChanged.connect(self._on_dev_changed)
        self._known_devs = set(glob.glob('/dev/plin*'))

    def _on_dev_changed(self, _path: str):
        """Wird aufgerufen wenn sich /dev/ aendert — plin*-Geraete pruefen."""
        current = set(glob.glob('/dev/plin*'))
        if current == self._known_devs:
            return

        added = current - self._known_devs
        removed = self._known_devs - current
        self._known_devs = current

        # Dropdown aktualisieren (nur wenn nicht verbunden)
        if self._plin is None:
            prev = self._iface_combo.currentText()
            self._iface_combo.clear()
            devs = sorted(current) if current else ['/dev/plin0']
            self._iface_combo.addItems(devs)
            if prev in devs:
                self._iface_combo.setCurrentText(prev)

        # Benutzer informieren
        if added:
            names = ', '.join(sorted(added))
            self._device_label.setText(f"PCAN USB PRO FD (LIN) — {names} erkannt")
            self._device_label.setStyleSheet(
                "color: #4CAF50; font-weight: bold; font-size: 11px;"
                "  padding: 3px 8px; background: transparent;")
            _log.info("PLIN-Geraet(e) hinzugefuegt: %s", names)
        elif removed:
            names = ', '.join(sorted(removed))
            self._device_label.setText(f"PCAN USB PRO FD (LIN) — {names} entfernt")
            self._device_label.setStyleSheet(
                "color: #F44336; font-weight: bold; font-size: 11px;"
                "  padding: 3px 8px; background: transparent;")
            _log.warning("PLIN-Geraet(e) entfernt: %s", names)

            # Verbindung trennen wenn aktives Geraet entfernt
            if self._plin is not None:
                active = self._iface_combo.currentText()
                if active in removed:
                    _log.error("Aktives Geraet %s entfernt — Verbindung trennen",
                               active)
                    self._connect_btn.setChecked(False)

        # Label nach 5s zuruecksetzen
        QTimer.singleShot(5000, self._reset_device_label)

    def _reset_device_label(self):
        """Setzt das Geraete-Label auf den Standard zurueck."""
        self._device_label.setText("PCAN USB PRO FD (LIN)")
        self._device_label.setStyleSheet(
            "color: #e8560a; font-weight: bold; font-size: 11px;"
            "  padding: 3px 8px; background: transparent;")

    # ── Konfigurationspanel ─────────────────────────────────────────────

    def _create_config_panel(self) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # ── Toggle-Zeile: Konfiguration + PCAN USB PRO FD (LIN) ──
        toggle_row = QHBoxLayout()
        toggle_row.setContentsMargins(0, 0, 0, 0)
        toggle_row.setSpacing(0)

        self._config_toggle = QPushButton("\u25bc Konfiguration")
        self._config_toggle.setCheckable(True)
        self._config_toggle.setChecked(True)
        self._config_toggle.setStyleSheet(
            "QPushButton { text-align: left; padding: 3px 8px;"
            "  font-weight: bold; font-size: 11px; border: none;"
            "  border-bottom: 1px solid palette(mid); }"
            "QPushButton:hover { background: palette(midlight); }")
        self._config_toggle.toggled.connect(self._on_config_toggle)
        toggle_row.addWidget(self._config_toggle)

        self._device_label = QLabel("PCAN USB PRO FD (LIN)")
        self._device_label.setStyleSheet(
            "color: #e8560a; font-weight: bold; font-size: 11px;"
            "  padding: 3px 8px; background: transparent;")
        toggle_row.addWidget(self._device_label)
        toggle_row.addStretch()

        wrapper_layout.addLayout(toggle_row)

        # ── Faltbarer Inhalt ──
        self._config_content = QWidget()
        self._config_content.setStyleSheet(NATIVE_COMBO_CSS)
        clayout = QVBoxLayout(self._config_content)
        clayout.setContentsMargins(8, 4, 8, 4)
        clayout.setSpacing(4)

        # Zeile 1: Schnittstelle + Bitrate + Modus + Pruefsumme
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        lbl_if = QLabel("Schnittstelle:")
        row1.addWidget(lbl_if)
        self._iface_combo = NativeComboBox()
        self._iface_combo.lineEdit().setReadOnly(False)
        self._iface_combo.addItems(get_lin_interfaces())
        self._iface_combo.setFixedWidth(91)
        row1.addWidget(self._iface_combo)

        lbl_br = QLabel("Bitrate:")
        row1.addWidget(lbl_br)
        self._bitrate_combo = NativeComboBox()
        self._bitrate_combo.lineEdit().setReadOnly(False)
        self._bitrate_combo.addItems(_BAUDRATES)
        self._bitrate_combo.setCurrentText("19200")
        self._bitrate_combo.setMinimumWidth(60)
        row1.addWidget(self._bitrate_combo)

        lbl_mode = QLabel("Modus:")
        row1.addWidget(lbl_mode)
        self._mode_combo = NativeComboBox()
        self._mode_combo.addItems(["Master", "Slave"])
        self._mode_combo.setCurrentText("Master")
        self._mode_combo.setMinimumWidth(80)
        row1.addWidget(self._mode_combo)

        lbl_cksum = QLabel("Prüfsumme:")
        row1.addWidget(lbl_cksum)
        self._checksum_combo = NativeComboBox()
        self._checksum_combo.addItems(["Enhanced (LIN 2.x)", "Classic (LIN 1.3)"])
        self._checksum_combo.setCurrentText("Enhanced (LIN 2.x)")
        self._checksum_combo.setMinimumWidth(140)
        row1.addWidget(self._checksum_combo)

        # Platzhalter fuer Bus-Toolbar-Buttons (Record, Filter Reset, Pause)
        self._bus_btn_layout = QHBoxLayout()
        self._bus_btn_layout.setSpacing(4)
        row1.addLayout(self._bus_btn_layout)

        # Verbinden + Start/Stop: Werden erstellt, aber vom WiresharkPanel
        # in die Toolbar-Zeile verschoben (reparented)
        self._connect_btn = QPushButton("Verbinden")
        self._connect_btn.setCheckable(True)
        self._connect_btn.setStyleSheet(_BTN_CONNECT_CHECKED)
        self._connect_btn.setMinimumWidth(100)
        self._connect_btn.toggled.connect(self._on_connect_toggled)

        self._status_indicator = QLabel("\u25cf Getrennt")
        self._status_indicator.setStyleSheet(
            "color: #F44336; font-weight: bold;")

        # Zyklisch: Intervall bleibt in Config-Zeile
        self._periodic_layout = QHBoxLayout()
        self._periodic_layout.setSpacing(4)
        self._periodic_layout.addWidget(QLabel("Zyklisch:"))
        self._per_interval = QSpinBox()
        self._per_interval.setRange(1, 60000)
        self._per_interval.setValue(100)
        self._per_interval.setSuffix(" ms")
        self._per_interval.setMaximumWidth(100)
        self._periodic_layout.addWidget(self._per_interval)
        row1.addLayout(self._periodic_layout)

        self._per_start = QPushButton("\u25b6 Start")
        self._per_start.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;")
        self._per_start.clicked.connect(self._start_periodic)
        self._per_start.setEnabled(False)
        self._per_start.setMinimumWidth(80)

        self._per_stop = QPushButton("\u2b1b Stop")
        self._per_stop.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;")
        self._per_stop.clicked.connect(self._stop_periodic)
        self._per_stop.setEnabled(False)
        self._per_stop.setMinimumWidth(80)

        self._ldf_btn = QPushButton('LDF...')
        self._ldf_btn.setToolTip('LDF-Datei laden fuer LIN-Nachrichtennamen')
        self._ldf_btn.setMinimumWidth(65)
        self._ldf_btn.clicked.connect(self._load_ldf)
        row1.addWidget(self._ldf_btn)

        # Template Save/Load
        self._tpl_save_btn = QPushButton('\U0001F4BE Speichern')
        self._tpl_save_btn.setToolTip('TX-Konfiguration als Template speichern')
        self._tpl_save_btn.setMinimumWidth(90)
        self._tpl_save_btn.clicked.connect(self._save_tx_template)
        row1.addWidget(self._tpl_save_btn)

        self._tpl_load_btn = QPushButton('\U0001F4C2 Laden')
        self._tpl_load_btn.setToolTip('TX-Template laden')
        self._tpl_load_btn.setMinimumWidth(80)
        self._tpl_load_btn.clicked.connect(self._load_tx_template)
        row1.addWidget(self._tpl_load_btn)

        # Statistics Toggle
        self._stats_btn = QPushButton('Statistik')
        self._stats_btn.setCheckable(True)
        self._stats_btn.setMinimumWidth(80)
        self._stats_btn.setToolTip('Echtzeit LIN-Statistik (TX/RX-Rate + Per-ID)')
        self._stats_btn.toggled.connect(self._toggle_stats)
        row1.addWidget(self._stats_btn)

        row1.addStretch()

        clayout.addLayout(row1)

        # Zeile 2: TX-Konfiguration (ID, DLC, Daten, Senden)
        row2 = QHBoxLayout()
        row2.setSpacing(6)

        row2.addWidget(QLabel("ID:"))
        self._tx_id = QLineEdit("0x00")
        self._tx_id.setMaximumWidth(90)
        self._tx_id.setFont(_MONO)
        row2.addWidget(self._tx_id)

        row2.addWidget(QLabel("DLC:"))
        self._tx_dlc = QSpinBox()
        self._tx_dlc.setRange(0, 8)
        self._tx_dlc.setValue(8)
        self._tx_dlc.setMaximumWidth(55)
        row2.addWidget(self._tx_dlc)

        row2.addWidget(QLabel("Daten:"))
        self._tx_data = QLineEdit("00 11 22 33 44 55 66 77")
        self._tx_data.setFont(_MONO)
        self._tx_data.setPlaceholderText("00 11 22 33 ...")
        row2.addWidget(self._tx_data, 1)

        self._send_btn = QPushButton("\u25b6 Senden")
        self._send_btn.clicked.connect(self._send_frame)
        self._send_btn.setEnabled(False)
        self._send_btn.setMinimumWidth(90)
        row2.addWidget(self._send_btn)

        clayout.addLayout(row2)

        wrapper_layout.addWidget(self._config_content)
        return wrapper

    def add_bus_button(self, widget):
        """Fuegt ein Widget (z.B. Record, Pause) in die Konfig-Zeile ein."""
        self._bus_btn_layout.addWidget(widget)

    def set_bus_row_counter_ref(self, counters: list, index: int):
        """Setzt Referenz auf bus_row_counters fuer RX-Ratenberechnung."""
        self._bus_row_counters = counters
        self._bus_index = index

    def set_plp_counter_ref(self, plp_pkt_counters: list,
                            plp_can_counters: list, index: int):
        """Setzt Referenz auf PLP-Zaehler fuer Ratenberechnung."""
        self._plp_counters = plp_pkt_counters
        self._plp_frame_counters = plp_can_counters
        self._plp_index = index

    # ── TX Templates ──

    def _save_tx_template(self):
        from core.tx_template_manager import save_template
        name, ok = QInputDialog.getText(
            self, "Template speichern", "Template-Name:")
        if not ok or not name.strip():
            return
        frame = {
            'id': self._tx_id.text(),
            'dlc': self._tx_dlc.value(),
            'data': self._tx_data_edit.text(),
            'cycle_ms': self._per_interval.value(),
        }
        path = save_template('LIN', name.strip(), [frame])
        QMessageBox.information(
            self, "Template", f"Template gespeichert:\n{path}")

    def _load_tx_template(self):
        from core.tx_template_manager import list_templates
        templates = list_templates('LIN')
        if not templates:
            QMessageBox.information(
                self, "Template", "Keine LIN-Templates vorhanden.")
            return
        names = [t['name'] for t in templates]
        name, ok = QInputDialog.getItem(
            self, "Template laden", "Template:", names, 0, False)
        if not ok:
            return
        idx = names.index(name)
        f = templates[idx].get('frames', [{}])[0]
        self._tx_id.setText(f.get('id', '0x00'))
        self._tx_dlc.setValue(f.get('dlc', 8))
        self._tx_data_edit.setText(f.get('data', ''))
        self._per_interval.setValue(f.get('cycle_ms', 100))

    def set_source_iface_ref(self, ifaces: list, protos: list, index: int):
        """Setzt Referenz auf bus_source_ifaces/protos fuer RX-Header."""
        self._source_ifaces = ifaces
        self._source_protos = protos
        self._source_iface_index = index
        self._last_shown_src = ""

    def _on_config_toggle(self, expanded: bool):
        """Konfigurationspanel auf-/zuklappen."""
        self._config_content.setVisible(expanded)
        self._config_toggle.setText(
            "\u25bc Konfiguration" if expanded else "\u25b6 Konfiguration")


    def _load_ldf(self):
        """LDF-Datei laden fuer LIN Frame-Namen."""
        path, _ = QFileDialog.getOpenFileName(
            self, "LDF-Datei laden", "",
            "LDF-Dateien (*.ldf);;DBC-Dateien (*.dbc);;Alle Dateien (*)")
        if not path:
            return
        try:
            self._ldf = cantools.database.load_file(path)
            self._ldf_name = os.path.basename(path)
            self._ldf_btn.setText('LDF \u2714')
            self._ldf_btn.setToolTip(
                f'{self._ldf_name}\n'
                f'{len(self._ldf.messages)} Nachrichten geladen')
            QSettings('ViGEM', 'LiveCapture').setValue('ldf/last_path', path)
            _log.info("LDF geladen: %s (%d Nachrichten)",
                       self._ldf_name, len(self._ldf.messages))
            parent = self.parent()
            while parent is not None:
                if hasattr(parent, '_lin_ldf'):
                    parent._lin_ldf = self._ldf
                    break
                parent = parent.parent()
        except Exception as e:
            _log.error("LDF laden fehlgeschlagen: %s", e)
            QMessageBox.warning(self, "LDF-Fehler", str(e))

    def _auto_load_ldf(self):
        """Laedt die zuletzt verwendete LDF-Datei automatisch."""
        path = QSettings('ViGEM', 'LiveCapture').value('ldf/last_path', '', type=str)
        if not path or not os.path.isfile(path):
            return
        try:
            self._ldf = cantools.database.load_file(path)
            self._ldf_name = os.path.basename(path)
            self._ldf_btn.setText('LDF \u2714')
            self._ldf_btn.setToolTip(
                f'{self._ldf_name}\n'
                f'{len(self._ldf.messages)} Nachrichten (auto-geladen)')
            _log.info("LDF auto-geladen: %s", path)
            parent = self.parent()
            while parent is not None:
                if hasattr(parent, '_lin_ldf'):
                    parent._lin_ldf = self._ldf
                    break
                parent = parent.parent()
        except Exception as e:
            _log.warning("LDF auto-laden fehlgeschlagen: %s", e)

    def ldf_lookup(self, frame_id: int) -> str:
        """Gibt den LDF-Frame-Namen fuer eine LIN-ID zurueck."""
        if self._ldf is None:
            return ""
        try:
            msg = self._ldf.get_message_by_frame_id(frame_id)
            return msg.name
        except (KeyError, AttributeError):
            return ""

    # ── TX-Bereich ──────────────────────────────────────────────────────

    def _create_tx_section(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # TX-Header mit Aktiv/Tx|Rx/Rate
        tx_header_widget = QWidget()
        tx_header_widget.setFixedHeight(22)
        tx_header_widget.setStyleSheet(
            "background-color: #1565C0; color: white;")
        tx_header_layout = QHBoxLayout(tx_header_widget)
        tx_header_layout.setContentsMargins(4, 0, 4, 0)
        tx_header_layout.setSpacing(8)

        tx_title = QLabel("TX \u2014 Sende-Konfiguration")
        tx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        tx_header_layout.addWidget(tx_title)

        self._per_label = QLabel("")
        self._per_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        tx_header_layout.addWidget(self._per_label)

        self._tx_status = QLabel("TX: 0 | RX: 0")
        self._tx_status.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        tx_header_layout.addWidget(self._tx_status)

        tx_header_layout.addStretch()

        self._tx_rate_label = QLabel("0 paket/s")
        self._tx_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        tx_header_layout.addWidget(self._tx_rate_label)

        layout.addWidget(tx_header_widget)

        # TX-Tabelle
        self._tx_table = QTableWidget()
        self._tx_table.setColumnCount(8)
        self._tx_table.setHorizontalHeaderLabels(_TX_HEADERS)
        self._tx_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._tx_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tx_table.setFont(QFont("Consolas", 9))
        self._tx_table.setStyleSheet(
            "QTableWidget { background-color: #ffffff; color: #1a1a1a;"
            "  gridline-color: #bbdefb; }"
            "QTableWidget::item:selected { background-color: #1565c0;"
            "  color: #ffffff; }"
            "QHeaderView::section { background: #f5f5f7; color: #0d0d17;"
            "  padding: 4px 6px; border: none;"
            "  border-right: 1px solid #d0d0d8;"
            "  border-bottom: 1px solid #333333;"
            "  font-weight: bold; }")
        self._tx_table.setShowGrid(True)
        self._tx_table.verticalHeader().setVisible(False)
        self._tx_table.verticalHeader().setDefaultSectionSize(22)
        h = self._tx_table.horizontalHeader()
        _widths = [180, 120, 70, 80, 100, 50, 800, 100]
        for col, w in enumerate(_widths):
            h.setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
                if col == 6 else QHeaderView.ResizeMode.Interactive)
            self._tx_table.setColumnWidth(col, w)

        # Leere Zeilen fuer initiale blau/weiss Anzeige
        for r in range(30):
            self._tx_table.insertRow(r)
            bg = QColor("#e3f2fd") if r % 2 == 0 else QColor("#ffffff")
            for c in range(8):
                item = QTableWidgetItem("")
                item.setBackground(bg)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
                self._tx_table.setItem(r, c, item)

        layout.addWidget(self._tx_table, 1)

        return widget

    # ═══════════════════════════════════════════════════════════════════
    # Verbindung
    # ═══════════════════════════════════════════════════════════════════

    def _on_connect_toggled(self, checked):
        if checked:
            self._connect_device()
        else:
            self._disconnect_device()

    def _is_enhanced_checksum(self) -> bool:
        """Gibt True zurueck wenn Enhanced (LIN 2.x) Pruefsumme gewaehlt."""
        return self._checksum_combo.currentText().startswith("Enhanced")

    def _get_plin_mode(self):
        """Gibt PLINMode.MASTER oder PLINMode.SLAVE zurueck."""
        if not PLIN_AVAILABLE:
            return None
        if self._mode_combo.currentText() == "Master":
            return PLINMode.MASTER
        return PLINMode.SLAVE

    def _connect_device(self):
        if not PLIN_AVAILABLE:
            QMessageBox.warning(
                self, "Fehler",
                "plin-linux nicht installiert.\n\n"
                "Installation:\n"
                "  pip install plin-linux\n\n"
                "Danach LiveCapture neu starten.")
            self._connect_btn.setChecked(False)
            return

        device_path = self._iface_combo.currentText().strip()

        # Pruefen ob das Geraet existiert
        if not os.path.exists(device_path):
            available = sorted(glob.glob('/dev/plin*'))
            if available:
                hint = (
                    f"Verfuegbare Geraete:\n"
                    f"  {', '.join(available)}\n\n"
                    f"Bitte ein vorhandenes Geraet auswaehlen.")
            else:
                hint = (
                    "Keine /dev/plin* Geraete gefunden.\n\n"
                    "\u2022 PCAN-USB Pro FD angeschlossen?\n"
                    "\u2022 PLIN-Treiber geladen? (modprobe peak_usb)\n"
                    "\u2022 Kernel-Modul: lsmod | grep peak")
            QMessageBox.warning(
                self, "Geraet nicht gefunden",
                f"'{device_path}' existiert nicht.\n\n{hint}")
            self._connect_btn.setChecked(False)
            return

        try:
            baudrate = int(self._bitrate_combo.currentText().strip())
        except ValueError:
            QMessageBox.warning(self, "Fehler", "Ungueltige Bitrate")
            self._connect_btn.setChecked(False)
            return

        mode = self._get_plin_mode()

        try:
            self._plin = PLIN(device_path)
            self._plin.start(mode=mode, baudrate=baudrate)
        except PermissionError:
            QMessageBox.warning(
                self, "Zugriff verweigert",
                f"Keine Berechtigung fuer '{device_path}'.\n\n"
                "Loesung:\n"
                f"  sudo chmod 666 {device_path}\n"
                "oder Benutzer zur Gruppe 'dialout' hinzufuegen:\n"
                f"  sudo usermod -aG dialout $USER")
            self._connect_btn.setChecked(False)
            self._plin = None
            return
        except Exception as e:
            QMessageBox.warning(
                self, "Verbindungsfehler",
                f"'{device_path}' konnte nicht geoeffnet werden.\n\n"
                f"{e}\n\n"
                "\u2022 PCAN-USB Pro FD angeschlossen?\n"
                "\u2022 PLIN-Treiber geladen?\n"
                f"\u2022 Zugriffsrechte auf {device_path}?")
            self._connect_btn.setChecked(False)
            self._plin = None
            return

        self._rx_thread = LinReceiveThread(self._plin, self)
        self._rx_thread.frame_received.connect(self._on_frame_received)
        self._rx_thread.error_occurred.connect(self._on_rx_error)
        self._rx_thread.start()
        self._start_time = time.time()

        # UI aktualisieren
        self._status_indicator.setText("\u25cf Verbunden")
        self._status_indicator.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self._connect_btn.setText("Trennen")
        self._send_btn.setEnabled(True)
        self._per_start.setEnabled(True)

        for w in (self._iface_combo, self._bitrate_combo,
                  self._mode_combo, self._checksum_combo):
            w.setEnabled(False)

    def _disconnect_device(self):
        self._stop_periodic()

        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
            self._rx_thread = None

        if self._plin is not None:
            try:
                self._plin.stop()
            except Exception:
                pass
            self._plin = None

        self._status_indicator.setText("\u25cf Getrennt")
        self._status_indicator.setStyleSheet("color: #F44336; font-weight: bold;")
        self._connect_btn.setText("Verbinden")
        self._send_btn.setEnabled(False)
        self._per_start.setEnabled(False)
        self._per_stop.setEnabled(False)

        for w in (self._iface_combo, self._bitrate_combo,
                  self._mode_combo, self._checksum_combo):
            w.setEnabled(True)

    # ═══════════════════════════════════════════════════════════════════
    # Senden
    # ═══════════════════════════════════════════════════════════════════

    def _parse_lin_id(self):
        """Parst LIN-ID (0x00–0x3F) aus dem Eingabefeld."""
        text = self._tx_id.text().strip()
        try:
            val = int(text, 16) if text.lower().startswith('0x') else int(text)
        except ValueError:
            return None
        if val < 0 or val > 0x3F:
            return None
        return val

    def _parse_hex_data(self):
        text = self._tx_data.text().strip().replace(' ', '')
        if len(text) % 2 != 0:
            text = text[:-1]
        try:
            return bytes.fromhex(text) if text else b''
        except ValueError:
            return None

    def _send_frame(self) -> bool:
        """Sendet einen LIN-Frame. Gibt True bei Erfolg zurueck."""
        if self._plin is None:
            return False

        lin_id = self._parse_lin_id()
        if lin_id is None:
            QMessageBox.warning(
                self, "Fehler",
                "Ungueltige LIN-ID (gueltig: 0x00–0x3F)")
            return False
        data = self._parse_hex_data()
        if data is None:
            QMessageBox.warning(self, "Fehler", "Ungueltige Hex-Daten")
            return False

        # Auf DLC begrenzen
        dlc = self._tx_dlc.value()
        data = data[:dlc]

        enhanced = self._is_enhanced_checksum()
        checksum = _calc_checksum(data, pid=lin_id, enhanced=enhanced)

        try:
            checksum_type = (
                PLINFrameChecksumType.ENHANCED if enhanced
                else PLINFrameChecksumType.CLASSIC
            )
            msg = PLINMessage()
            msg.id = lin_id
            msg.len = len(data)
            msg.dir = PLINFrameDirection.PUBLISHER
            msg.cs_type = checksum_type
            msg.data = data

            # Non-blocking write to prevent GUI freeze in Slave mode
            import os as _os
            fd = self._plin.fd
            if fd:
                _os.set_blocking(fd, False)
            try:
                self._plin.write(msg)
            except BlockingIOError:
                _log.warning("LIN-Senden blockiert (Slave ohne Master?)")
                return False
            finally:
                if fd:
                    _os.set_blocking(fd, True)

            # Re-enable receiving this ID (write() calls block_id internally)
            self._plin.register_id(lin_id)

            self._tx_count += 1
            self._tx_reference[lin_id] = bytes(data)
            if self._stats_widget:
                self._stats_widget.record_tx()

            # Per-ID TX-Statistik
            if lin_id not in self._id_stats:
                self._id_stats[lin_id] = {
                    'rx_count': 0, 'tx_count': 0, 'err_count': 0,
                    'last_rx': 0.0, 'last_tx': 0.0,
                    'last_rx_rate': 0.0, 'prev_rx_count': 0,
                }
            self._id_stats[lin_id]['tx_count'] += 1
            self._id_stats[lin_id]['last_tx'] = time.time()

            elapsed = time.time() - (self._start_time or time.time())
            self._add_tx_row(lin_id, data, elapsed, checksum)
            self._update_counters()
            self._consecutive_errors = 0
            return True
        except Exception as e:
            _log.error("LIN-Senden: %s", e)
            if self._stats_widget:
                self._stats_widget.record_error()
            return False

    def _start_periodic(self):
        if self._plin is None:
            return
        self._stop_periodic()
        self._periodic_count = 0
        self._consecutive_errors = 0
        self._periodic_timer = QTimer(self)
        self._periodic_timer.timeout.connect(self._on_periodic_tick)
        self._periodic_timer.start(self._per_interval.value())
        self._per_start.setEnabled(False)
        self._per_stop.setEnabled(True)
        self._per_label.setText("Aktiv: 0")


    def _stop_periodic(self):
        if self._periodic_timer is not None:
            self._periodic_timer.stop()
            self._periodic_timer.deleteLater()
            self._periodic_timer = None
        self._per_start.setEnabled(self._plin is not None)
        self._per_stop.setEnabled(False)
        if self._periodic_count > 0:
            self._per_label.setText(f"Gestoppt: {self._periodic_count}")


    def _on_periodic_tick(self):
        ok = self._send_frame()
        if ok:
            self._periodic_count += 1
            self._per_label.setText(f"Aktiv: {self._periodic_count}")

        else:
            self._consecutive_errors = getattr(self, '_consecutive_errors', 0) + 1
            if self._consecutive_errors >= 3:
                self._stop_periodic()
                self._per_label.setText("FEHLER: TX-Puffer voll")

                _log.error(
                    "Zyklisches Senden gestoppt: %d aufeinanderfolgende"
                    " Fehler (ENOBUFS / Error 105)",
                    self._consecutive_errors)

    # ═══════════════════════════════════════════════════════════════════
    # Empfang → bus_queues
    # ═══════════════════════════════════════════════════════════════════

    def _on_frame_received(self, frame: dict):
        """Empfangener Frame → Signal fuer bus_queues."""
        self._rx_count += 1
        if self._stats_widget:
            self._stats_widget.record_rx()

        # Per-ID Statistik aktualisieren
        lin_id = frame.get('lin_id', 0)
        now = time.time()
        if lin_id not in self._id_stats:
            self._id_stats[lin_id] = {
                'rx_count': 0, 'tx_count': 0, 'err_count': 0,
                'last_rx': 0.0, 'last_tx': 0.0,
                'last_rx_rate': 0.0, 'prev_rx_count': 0,
            }
        entry = self._id_stats[lin_id]
        entry['rx_count'] += 1
        entry['last_rx'] = now

        ts = frame['timestamp']
        if self._start_time and ts > 1e9:
            ts = ts - self._start_time

        lin_id = frame['lin_id']
        data = frame.get('data', b'')
        data_hex = ' '.join(f'{b:02X}' for b in data)
        id_str = f"0x{lin_id:02X}"
        channel = self._iface_combo.currentText()

        enhanced = self._is_enhanced_checksum()
        rx_checksum = frame.get('checksum')
        if rx_checksum is None:
            rx_checksum = _calc_checksum(
                data, pid=lin_id, enhanced=enhanced)
        checksum_str = f"0x{rx_checksum:02X}"

        # Differenz-Check
        if lin_id in self._tx_reference:
            tx_data = self._tx_reference[lin_id]
            if data != tx_data:
                tx_hex = ' '.join(f'{b:02X}' for b in tx_data)
                checksum_str += f" [DIFF vs TX: {tx_hex}]"

        # Bus-Queue Format: (zeit, kanal, id, name, dlc, daten, pruefsumme)
        row_tuple = (
            f"{ts:.6f}",
            channel,
            id_str,
            self.ldf_lookup(frame.get("lin_id", 0)),  # Name (LDF)
            str(frame.get('dlc', len(data))),
            data_hex,
            f"PLIN {checksum_str}",
        )
        self.frame_for_bus_queue.emit(row_tuple)
        self._update_counters()

    def _on_rx_error(self, error):
        _log.error("PLIN RX-Fehler: %s", error)
        if self._stats_widget:
            self._stats_widget.record_error()

    # ═══════════════════════════════════════════════════════════════════
    # TX-Tabelle
    # ═══════════════════════════════════════════════════════════════════

    def _add_tx_row(self, lin_id: int, data: bytes,
                    elapsed: float, checksum: int):
        row = (self._tx_count - 1) % 30

        id_str = f"0x{lin_id:02X}"
        data_hex = ' '.join(f'{b:02X}' for b in data)
        channel = self._iface_combo.currentText()
        checksum_str = f"0x{checksum:02X}"

        cells = [
            str(self._tx_count), f"{elapsed:.6f}", channel,
            id_str, "", str(len(data)), data_hex, checksum_str,
        ]
        for col, text in enumerate(cells):
            item = self._tx_table.item(row, col)
            if item is not None:
                item.setText(text)

    def _update_counters(self):
        rx = self._bus_row_counters[self._bus_index] if self._bus_row_counters else self._rx_count
        self._tx_status.setText(f"TX: {self._tx_count} | RX: {rx}")

    # ═══════════════════════════════════════════════════════════════════
    # Ratenberechnung
    # ═══════════════════════════════════════════════════════════════════

    def _update_rates(self):
        """Berechnet TX/RX-Rate in Paketen pro Sekunde."""
        tx_rate = self._tx_count - self._last_tx_count
        self._last_tx_count = self._tx_count
        self._tx_rate_label.setText(f"{tx_rate} paket/s")

        # RX-Rate: bus_row_counters erfasst ALLE Quellen (PLIN + TECMP)
        if self._bus_row_counters is not None:
            current = self._bus_row_counters[self._bus_index]
            rx_rate = current - self._last_bus_row_count
            self._last_bus_row_count = current
        else:
            rx_rate = self._rx_count - self._last_rx_count
            self._last_rx_count = self._rx_count
        self._tx_rate_label.setText(f"{tx_rate} paket/s")
        self._rx_rate_label.setText(f"{rx_rate} paket/s")

        # RX-Titel: Quell-Interface + Protokoll anzeigen
        if hasattr(self, '_source_ifaces'):
            idx = self._source_iface_index
            iface = self._source_ifaces[idx]
            proto = self._source_protos[idx] if hasattr(self, '_source_protos') else ''
            src_key = f"{iface}:{proto}"
            if src_key != self._last_shown_src and (iface or proto):
                self._last_shown_src = src_key
                parts = [x for x in (iface, proto) if x]
                self._rx_title.setText(
                    f"RX \u2014 Empfangene Daten ({', '.join(parts)})")

    # ═══════════════════════════════════════════════════════════════════
    # Statistik
    # ═══════════════════════════════════════════════════════════════════

    def _toggle_stats(self, checked: bool):
        if checked:
            if self._stats_widget is None:
                from ui.widgets.bus_statistics_widget import BusStatisticsWidget
                self._stats_widget = BusStatisticsWidget('LIN', self)
            if self._id_stats_widget is None:
                self._id_stats_widget = LinIdStatsWidget(self)
                self._id_stats_widget.set_ldf_lookup(self.ldf_lookup)
            # Einfuegen nach config_widget (Position 1 und 2)
            main_layout = self.layout()
            main_layout.insertWidget(1, self._stats_widget)
            main_layout.insertWidget(2, self._id_stats_widget)
            self._stats_widget.show()
            self._id_stats_widget.show()
            # Per-ID Tabelle regelmaessig aktualisieren
            if not hasattr(self, '_id_stats_timer'):
                self._id_stats_timer = QTimer(self)
                self._id_stats_timer.setInterval(1000)
                self._id_stats_timer.timeout.connect(self._update_id_stats)
            self._id_stats_timer.start()
        else:
            if self._stats_widget is not None:
                self._stats_widget.hide()
            if self._id_stats_widget is not None:
                self._id_stats_widget.hide()
            if hasattr(self, '_id_stats_timer'):
                self._id_stats_timer.stop()

    def _update_id_stats(self):
        """Aktualisiert die Per-ID-Statistiktabelle."""
        if self._id_stats_widget is None:
            return
        # Raten berechnen (Delta pro Sekunde)
        now = time.time()
        for entry in self._id_stats.values():
            entry['last_rx_rate'] = entry['rx_count'] - entry['prev_rx_count']
            entry['prev_rx_count'] = entry['rx_count']
        self._id_stats_widget.update_data(self._id_stats, now)

    # ═══════════════════════════════════════════════════════════════════
    # Bereinigung
    # ═══════════════════════════════════════════════════════════════════

    def cleanup(self):
        """Muss von aussen aufgerufen werden (z.B. closeEvent)."""
        self._rate_timer.stop()
        self._stop_periodic()
        if hasattr(self, '_id_stats_timer'):
            self._id_stats_timer.stop()
        if self._stats_widget is not None:
            self._stats_widget.cleanup()
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
        if self._plin is not None:
            try:
                self._plin.stop()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# LinIdStatsWidget — Per-LIN-ID Statistik-Tabelle
# ═══════════════════════════════════════════════════════════════════════════

_ID_STATS_HEADERS = ["ID", "Name", "RX", "TX", "Fehler", "Rate (f/s)", "Letzte RX"]


class LinIdStatsWidget(QWidget):
    """Tabelle mit Statistik pro LIN-ID (0x00–0x3F)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ldf_lookup = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Header
        hdr = QHBoxLayout()
        hdr.setSpacing(8)
        title = QLabel("LIN Per-ID Statistik")
        title.setStyleSheet("font-weight: bold; font-size: 11px;")
        hdr.addWidget(title)

        self._id_count_label = QLabel("0 IDs aktiv")
        self._id_count_label.setFont(_MONO)
        hdr.addWidget(self._id_count_label)

        clear_btn = QPushButton("Zuruecksetzen")
        clear_btn.setMinimumWidth(100)
        clear_btn.clicked.connect(self._clear)
        hdr.addWidget(clear_btn)
        hdr.addStretch()
        layout.addLayout(hdr)

        # Tabelle
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(_ID_STATS_HEADERS)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setFont(_MONO)
        self._table.setStyleSheet(
            "QTableWidget { background-color: #ffffff; color: #1a1a1a;"
            "  gridline-color: #e0e0e0; }"
            "QTableWidget::item:selected { background-color: #1565c0;"
            "  color: #ffffff; }"
            "QHeaderView::section { background: #f5f5f7; color: #0d0d17;"
            "  padding: 4px 6px; border: none;"
            "  border-right: 1px solid #d0d0d8;"
            "  border-bottom: 1px solid #333333;"
            "  font-weight: bold; }")
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.setMinimumHeight(80)
        self._table.setMaximumHeight(200)

        h = self._table.horizontalHeader()
        _col_widths = [60, 150, 80, 80, 80, 90, 160]
        for col, w in enumerate(_col_widths):
            h.setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
                if col == 1 else QHeaderView.ResizeMode.Interactive)
            self._table.setColumnWidth(col, w)

        layout.addWidget(self._table, 1)

    def set_ldf_lookup(self, func):
        """Setzt die LDF-Lookup-Funktion fuer Frame-Namen."""
        self._ldf_lookup = func

    def _clear(self):
        """Signal an Parent zum Zuruecksetzen der ID-Statistik."""
        parent = self.parent()
        if hasattr(parent, '_id_stats'):
            parent._id_stats.clear()
        self._table.setRowCount(0)
        self._id_count_label.setText("0 IDs aktiv")

    def update_data(self, id_stats: Dict[int, dict], now: float):
        """Aktualisiert die Tabelle mit den neuesten Daten."""
        sorted_ids = sorted(id_stats.keys())
        self._id_count_label.setText(f"{len(sorted_ids)} IDs aktiv")

        self._table.setRowCount(len(sorted_ids))
        for row, lin_id in enumerate(sorted_ids):
            entry = id_stats[lin_id]
            name = self._ldf_lookup(lin_id) if self._ldf_lookup else ""
            rx_rate = entry.get('last_rx_rate', 0)
            last_rx = entry.get('last_rx', 0.0)
            age = now - last_rx if last_rx > 0 else -1

            if age < 0:
                age_str = "-"
            elif age < 1:
                age_str = "< 1s"
            elif age < 60:
                age_str = f"{age:.0f}s"
            else:
                age_str = f"{age / 60:.1f}min"

            cells = [
                f"0x{lin_id:02X}",
                name,
                str(entry.get('rx_count', 0)),
                str(entry.get('tx_count', 0)),
                str(entry.get('err_count', 0)),
                str(rx_rate),
                age_str,
            ]

            bg = QColor("#e3f2fd") if row % 2 == 0 else QColor("#ffffff")
            for col, text in enumerate(cells):
                item = self._table.item(row, col)
                if item is None:
                    item = QTableWidgetItem(text)
                    item.setBackground(bg)
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignCenter
                        | Qt.AlignmentFlag.AlignVCenter)
                    self._table.setItem(row, col, item)
                else:
                    item.setText(text)
                    item.setBackground(bg)

                # Farbkodierung: Fehler rot, aktive Rate gruen
                if col == 4 and entry.get('err_count', 0) > 0:
                    item.setForeground(QColor("#F44336"))
                elif col == 5 and rx_rate > 0:
                    item.setForeground(QColor("#4CAF50"))
