"""PCAN-USB Pro FD Konfiguration und TX/RX-Ansicht fuer Live CAN.

Integriert sich in die bestehende Live CAN Seite des WiresharkPanels:
- Faltbares Konfigurationspanel (Schnittstelle, Bitrate, CAN-FD, Loopback)
- TX-Bereich: Sende-Konfiguration + Sende-Historie
- Bestehendes CAN-TableView als RX-Bereich (mit BusTableModel + FilterHeader)
- Empfangene PCAN-Frames werden in bus_queues eingespeist
"""

import logging
import os
import re
import subprocess
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QCheckBox, QHeaderView,
    QGroupBox, QMessageBox, QTableView, QFileDialog,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt6.QtGui import QColor, QFont

from core.platform import get_can_interfaces
from ui.widgets.native_combo_box import NativeComboBox, NATIVE_COMBO_CSS

_log = logging.getLogger(__name__)

# ── python-can ──────────────────────────────────────────────────────────
try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False

# ── Konstanten ──────────────────────────────────────────────────────────
_BITRATES = ["125000", "250000", "500000", "1000000"]
_FD_BITRATES = ["1000000", "2000000", "4000000", "5000000", "8000000"]
_TX_HEADERS = ["Nr.", "Zeit", "Kanal", "ID", "Name", "DLC", "Daten", "Info"]

_MONO = QFont("Consolas", 9)
_MONO_BOLD = QFont("Consolas", 9, QFont.Weight.Bold)
_DIFF_FG = QColor(220, 50, 50)
_MAX_TX_ROWS = 5000

# ── Spezial-Styles (nur fuer besondere Zustaende) ────────────────────
_BTN_CONNECT_CHECKED = (
    "QPushButton:checked { background: #2E7D32; color: white; font-weight: bold; }"
)
_TX_ROW_BG = QColor(200, 220, 255)  # Helles Blau fuer TX-Zeilen


# ═══════════════════════════════════════════════════════════════════════════
# CAN-Empfangsthread
# ═══════════════════════════════════════════════════════════════════════════

class CanReceiveThread(QThread):
    """Empfaengt CAN-Nachrichten ueber python-can in einem Worker-Thread."""

    frame_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, bus, parent=None):
        super().__init__(parent)
        self._bus = bus
        self._running = True

    def run(self):
        while self._running:
            try:
                msg = self._bus.recv(timeout=0.1)
                if msg is not None:
                    self.frame_received.emit({
                        'timestamp': msg.timestamp,
                        'channel': str(msg.channel or ''),
                        'can_id': msg.arbitration_id,
                        'is_extended': msg.is_extended_id,
                        'dlc': msg.dlc,
                        'data': bytes(msg.data),
                        'is_fd': msg.is_fd,
                    })
            except Exception as e:
                if self._running:
                    self.error_occurred.emit(str(e))
                break

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# PcanCanPage — Wrapper fuer die CAN-Seite
# ═══════════════════════════════════════════════════════════════════════════

class PcanCanPage(QWidget):
    """Wrapper fuer die CAN-Seite mit PCAN-USB Pro FD Integration.

    Nimmt das bestehende CAN-TableView (BusTableModel) als RX-Bereich
    und fuegt PCAN-Konfiguration + TX-Bereich darueber.
    """

    # Signal: formatiertes Row-Tuple fuer bus_queues[0]
    # Format: (zeit, kanal, can_id, name, dlc, data_hex, info)
    frame_for_bus_queue = pyqtSignal(tuple)

    def __init__(self, existing_can_table: QTableView, parent=None):
        super().__init__(parent)
        self._existing_table = existing_can_table
        self._bus: Optional[object] = None
        self._rx_thread: Optional[CanReceiveThread] = None
        self._tx_count = 0
        self._rx_count = 0
        self._start_time: Optional[float] = None
        self._periodic_timer: Optional[QTimer] = None
        self._periodic_count = 0
        self._tx_reference: Dict[int, bytes] = {}
        self._dbc = None  # cantools Database
        self._signal_detail_visible = False
        self._plot_widget = None  # CanSignalPlotWidget
        self._dbc_name = ''  # geladener DBC-Dateiname
        self._last_tx_count = 0
        self._last_rx_count = 0
        self._bus_row_counters = None  # Wird von WiresharkPanel gesetzt
        self._bus_index = 0
        self._last_bus_row_count = 0
        self._prev_sysfs_rx = 0  # PLP-Paketrate aus sysfs
        self._smoothed_can_rate = 0.0  # EMA-geglaettete CAN-Rate
        self._smoothed_plp_rate = 0.0  # EMA-geglaettete PLP-Rate
        self._smoothed_tx_rate = 0.0   # EMA-geglaettete TX-Rate
        self._last_rate_time = 0.0     # Zeitstempel fuer Rate-Berechnung
        self._init_ui()

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

        # RX-Bereich: bestehendes CAN-TableView
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

        self._rx_title = QLabel("RX \u2014 Empfangene Daten (TECMP + PCAN)")
        rx_title = self._rx_title
        rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(rx_title)
        rx_header_layout.addStretch()

        self._bus_error_label = QLabel("")
        self._bus_error_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._bus_error_label)

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._can_rate_label = QLabel("CAN: 0 Frames/s")
        self._can_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._can_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)

        # ── Signal-Detail-Tabelle (DBC Decode) ──
        self._signal_table = QTableWidget()
        self._signal_table.setColumnCount(6)
        self._signal_table.setHorizontalHeaderLabels(
            ['Signal', 'Rohwert', 'Physikalisch', 'Einheit', 'Min', 'Max'])
        self._signal_table.setFont(QFont('Consolas', 9))
        self._signal_table.setMaximumHeight(120)
        self._signal_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._signal_table.horizontalHeader().setStretchLastSection(True)
        self._signal_table.verticalHeader().setVisible(False)
        self._signal_table.verticalHeader().setDefaultSectionSize(20)
        self._signal_table.hide()
        rx_layout.addWidget(self._signal_table)
        splitter.addWidget(rx_wrapper)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        # Selection-Signal verbinden
        try:
            self._existing_table.clicked.connect(self._on_rx_row_selected)
        except Exception:
            pass
        layout.addWidget(splitter, 1)

        # ── Raten-Timer (1x pro Sekunde) ──
        self._rate_timer = QTimer(self)
        self._rate_timer.setInterval(1000)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start()

        # ── DBC Auto-Load (QSettings) ──
        self._auto_load_dbc()

        # ── Bus-State-Timer (alle 2 Sekunden) ──
        self._bus_state_timer = QTimer(self)
        self._bus_state_timer.setInterval(2000)
        self._bus_state_timer.timeout.connect(self._check_bus_state)
        self._last_bus_state = ""
        self._recovery_attempts = 0
        self._max_recovery_attempts = 3
        self._last_error_stats = ""

    # ── Konfigurationspanel ─────────────────────────────────────────────

    def _create_config_panel(self) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # ── Toggle-Button zum Auf-/Zuklappen ──
        # ── Toggle-Zeile: Konfiguration + PCAN USB PRO FD ──
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

        self._device_label = QLabel("PCAN USB PRO FD")
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

        # Zeile 1: Schnittstelle + Bitrate
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        lbl_if = QLabel("Schnittstelle:")
        row1.addWidget(lbl_if)
        self._iface_combo = NativeComboBox()
        self._iface_combo.lineEdit().setReadOnly(False)
        self._iface_combo.addItems(get_can_interfaces())
        self._iface_combo.setFixedWidth(65)
        row1.addWidget(self._iface_combo)

        lbl_br = QLabel("Bitrate:")
        row1.addWidget(lbl_br)
        self._bitrate_combo = NativeComboBox()
        self._bitrate_combo.lineEdit().setReadOnly(False)
        self._bitrate_combo.addItems(_BITRATES)
        self._bitrate_combo.setCurrentText("500000")
        self._bitrate_combo.setMinimumWidth(90)
        row1.addWidget(self._bitrate_combo)

        self._fd_check = QCheckBox("CAN-FD-Bitrate:")
        self._fd_check.toggled.connect(self._on_fd_toggled)
        row1.addWidget(self._fd_check)
        self._fd_bitrate_combo = NativeComboBox()
        self._fd_bitrate_combo.lineEdit().setReadOnly(False)
        self._fd_bitrate_combo.addItems(_FD_BITRATES)
        self._fd_bitrate_combo.setCurrentText("2000000")
        self._fd_bitrate_combo.setEnabled(False)
        self._fd_bitrate_combo.setMinimumWidth(90)
        row1.addWidget(self._fd_bitrate_combo)

        self._loopback_check = QCheckBox("Loopback")
        row1.addWidget(self._loopback_check)

        # Platzhalter fuer Bus-Toolbar-Buttons (Record, Filter Reset, Pause)
        # und Zyklisch-Steuerung
        self._bus_btn_layout = QHBoxLayout()
        self._bus_btn_layout.setSpacing(4)
        row1.addLayout(self._bus_btn_layout)

        # ── Zyklisch-Steuerung (nach Pause) ──
        self._periodic_layout = QHBoxLayout()
        self._periodic_layout.setSpacing(4)

        self._periodic_layout.addWidget(QLabel("Zyklisch:"))
        self._per_interval = QSpinBox()
        self._per_interval.setRange(1, 60000)
        self._per_interval.setValue(100)
        self._per_interval.setSuffix(" ms")
        self._per_interval.setMaximumWidth(100)
        self._periodic_layout.addWidget(self._per_interval)

        self._per_start = QPushButton("Start")
        self._per_start.clicked.connect(self._start_periodic)
        self._per_start.setEnabled(False)
        self._per_start.setMinimumWidth(55)
        self._periodic_layout.addWidget(self._per_start)

        self._per_stop = QPushButton("Stopp")
        self._per_stop.clicked.connect(self._stop_periodic)
        self._per_stop.setEnabled(False)
        self._per_stop.setMinimumWidth(55)
        self._periodic_layout.addWidget(self._per_stop)

        row1.addLayout(self._periodic_layout)

        self._dbc_btn = QPushButton('DBC...')
        self._dbc_btn.setToolTip('DBC-Datei laden fuer CAN-Nachrichtennamen')
        self._dbc_btn.setMinimumWidth(65)
        self._dbc_btn.clicked.connect(self._load_dbc)
        row1.addWidget(self._dbc_btn)

        self._plot_btn = QPushButton('Plot')
        self._plot_btn.setCheckable(True)
        self._plot_btn.setMinimumWidth(60)
        self._plot_btn.setToolTip('CAN-Signal Echtzeit-Plot ein/ausblenden')
        self._plot_btn.toggled.connect(self._toggle_signal_plot)
        row1.addWidget(self._plot_btn)

        row1.addStretch()

        # Verbinden-Button
        self._connect_btn = QPushButton("Verbinden")
        self._connect_btn.setCheckable(True)
        self._connect_btn.setStyleSheet(_BTN_CONNECT_CHECKED)
        self._connect_btn.setMinimumWidth(110)
        self._connect_btn.toggled.connect(self._on_connect_toggled)
        row1.addWidget(self._connect_btn)

        self._status_indicator = QLabel("\u25cf Getrennt")
        self._status_indicator.setStyleSheet("color: #F44336; font-weight: bold;")
        row1.addWidget(self._status_indicator)

        clayout.addLayout(row1)

        # Zeile 2: TX-Konfiguration (ID, DLC, Daten, Senden)
        row2 = QHBoxLayout()
        row2.setSpacing(6)

        row2.addWidget(QLabel("ID:"))
        self._tx_id = QLineEdit("0x123")
        self._tx_id.setMaximumWidth(90)
        self._tx_id.setFont(_MONO)
        row2.addWidget(self._tx_id)

        self._tx_ext = QCheckBox("Ext")
        row2.addWidget(self._tx_ext)

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

    def set_plp_counter_ref(self, counters: list, index: int):
        """Setzt Referenz auf plp_packet_counters fuer PLP-Ratenberechnung."""
        self._plp_counters = counters
        self._plp_index = index
        self._last_plp_count = 0

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


    def _load_dbc(self):
        """DBC-Datei laden fuer CAN-ID → Nachrichtenname Dekodierung."""
        path, _ = QFileDialog.getOpenFileName(
            self, "DBC-Datei laden", "",
            "DBC-Dateien (*.dbc);;Alle Dateien (*)")
        if not path:
            return
        try:
            import cantools
            self._dbc = cantools.database.load_file(path)
            self._dbc_name = path.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
            self._dbc_btn.setText(f'DBC \u2714')
            self._dbc_btn.setToolTip(
                f'{self._dbc_name}\n'
                f'{len(self._dbc.messages)} Nachrichten geladen\n'
                'Erneut klicken zum Wechseln')
            QSettings('ViGEM', 'LiveCapture').setValue('dbc/last_path', path)
            _log.info("DBC geladen: %s (%d Nachrichten)",
                       self._dbc_name, len(self._dbc.messages))
            if self._plot_widget is not None:
                self._plot_widget.set_dbc(self._dbc)
            # Referenz an WiresharkPanel weitergeben
            parent = self.parent()
            while parent is not None:
                if hasattr(parent, '_can_dbc'):
                    parent._can_dbc = self._dbc
                    break
                parent = parent.parent()
        except Exception as e:
            _log.error("DBC laden fehlgeschlagen: %s", e)
            QMessageBox.warning(self, "DBC-Fehler", str(e))

    def dbc_lookup(self, can_id: int) -> str:
        """Gibt den DBC-Nachrichtennamen fuer eine CAN-ID zurueck."""
        if self._dbc is None:
            return ""
        try:
            msg = self._dbc.get_message_by_frame_id(can_id)
            return msg.name
        except KeyError:
            return ""


    def _auto_load_dbc(self):
        """Laedt die zuletzt verwendete DBC-Datei automatisch."""
        path = QSettings('ViGEM', 'LiveCapture').value('dbc/last_path', '', type=str)
        if not path or not os.path.isfile(path):
            return
        try:
            import cantools
            self._dbc = cantools.database.load_file(path)
            self._dbc_name = os.path.basename(path)
            self._dbc_btn.setText('DBC \u2714')
            self._dbc_btn.setToolTip(
                f'{self._dbc_name}\n'
                f'{len(self._dbc.messages)} Nachrichten (auto-geladen)')
            _log.info("DBC auto-geladen: %s", path)
            parent = self.parent()
            while parent is not None:
                if hasattr(parent, '_can_dbc'):
                    parent._can_dbc = self._dbc
                    break
                parent = parent.parent()
            if hasattr(self, '_plot_widget') and self._plot_widget is not None:
                self._plot_widget.set_dbc(self._dbc)
        except Exception as e:
            _log.warning("DBC auto-laden fehlgeschlagen: %s", e)

    def _on_rx_row_selected(self, index):
        """Zeigt DBC-dekodierte Signalwerte fuer die ausgewaehlte CAN-Zeile."""
        if self._dbc is None:
            self._signal_table.hide()
            return
        model = self._existing_table.model()
        if hasattr(model, 'mapToSource'):
            source_idx = model.mapToSource(index)
            source_model = model.sourceModel()
        else:
            source_idx = index
            source_model = model
        row = source_idx.row()
        if row < 0 or row >= source_model.rowCount():
            return
        try:
            row_data = source_model._rows[row]
            can_id_str = row_data[3]
            data_hex = row_data[6]
        except (IndexError, AttributeError):
            return
        if not can_id_str or not data_hex:
            return
        try:
            id_text = can_id_str.split(' ')[0]
            can_id = int(id_text, 16)
            data_bytes = bytes.fromhex(data_hex.replace(' ', ''))
        except (ValueError, AttributeError):
            return
        try:
            msg = self._dbc.get_message_by_frame_id(can_id)
            raw_vals = msg.decode(data_bytes, scaling=False)
            phys_vals = msg.decode(data_bytes, scaling=True)
        except (KeyError, Exception):
            self._signal_table.hide()
            return
        signals = msg.signals
        self._signal_table.setRowCount(len(signals))
        for i, sig in enumerate(signals):
            raw = raw_vals.get(sig.name, '')
            phys = phys_vals.get(sig.name, '')
            items = [
                sig.name,
                str(raw),
                f"{phys:.4f}" if isinstance(phys, float) else str(phys),
                sig.unit or '',
                str(sig.minimum) if sig.minimum is not None else '',
                str(sig.maximum) if sig.maximum is not None else '',
            ]
            for col, text in enumerate(items):
                self._signal_table.setItem(i, col, QTableWidgetItem(text))
        self._signal_table.resizeColumnsToContents()
        self._signal_table.show()

    def _toggle_signal_plot(self, checked: bool):
        """Blendet den CAN-Signal Echtzeit-Plot ein/aus."""
        if checked:
            if self._plot_widget is None:
                try:
                    from ui.widgets.can_signal_plot import CanSignalPlotWidget
                    self._plot_widget = CanSignalPlotWidget(self)
                    if self._dbc:
                        self._plot_widget.set_dbc(self._dbc)
                    self.layout().addWidget(self._plot_widget)
                except ImportError as e:
                    _log.error("Plot-Widget Import: %s", e)
                    self._plot_btn.setChecked(False)
                    return
            self._plot_widget.show()
        else:
            if self._plot_widget is not None:
                self._plot_widget.hide()

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

        self._bus_state_label = QLabel("")
        self._bus_state_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        tx_header_layout.addWidget(self._bus_state_label)

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

    def _on_fd_toggled(self, checked):
        self._fd_bitrate_combo.setEnabled(checked)
        self._tx_dlc.setRange(0, 64 if checked else 8)

    def _on_connect_toggled(self, checked):
        if checked:
            self._connect_device()
        else:
            self._disconnect_device()

    def _configure_interface(self, interface, bitrate,
                             fd=False, fd_bitrate=2000000,
                             loopback=False):
        """Konfiguriert CAN-Schnittstelle ueber ip link."""
        try:
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                capture_output=True, timeout=5)

            cmd = ['sudo', 'ip', 'link', 'set', interface,
                   'type', 'can', 'bitrate', str(bitrate)]
            if fd:
                cmd.extend(['dbitrate', str(fd_bitrate), 'fd', 'on'])
            if loopback:
                cmd.extend(['loopback', 'on'])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                _log.error("CAN-Konfig fehlgeschlagen: %s", result.stderr.strip())
                return False

            result = subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'up'],
                capture_output=True, text=True, timeout=5)
            return result.returncode == 0

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            _log.error("Interface-Konfiguration: %s", e)
            return False

    def _connect_device(self):
        if not CAN_AVAILABLE:
            QMessageBox.warning(
                self, "Fehler",
                "python-can nicht installiert.\npip install python-can")
            self._connect_btn.setChecked(False)
            return

        interface = self._iface_combo.currentText().strip()
        try:
            bitrate = int(self._bitrate_combo.currentText().strip())
        except ValueError:
            QMessageBox.warning(self, "Fehler", "Ungueltige Bitrate")
            self._connect_btn.setChecked(False)
            return

        fd = self._fd_check.isChecked()
        fd_bitrate = 2000000
        if fd:
            try:
                fd_bitrate = int(self._fd_bitrate_combo.currentText())
            except ValueError:
                pass
        loopback = self._loopback_check.isChecked()

        if not self._configure_interface(
                interface, bitrate, fd, fd_bitrate, loopback):
            QMessageBox.warning(
                self, "Verbindungsfehler",
                f"'{interface}' konnte nicht konfiguriert werden.\n\n"
                "\u2022 PCAN-USB Pro FD angeschlossen?\n"
                "\u2022 peak_usb Treiber geladen? (sudo modprobe peak_usb)\n"
                "\u2022 sudo-Berechtigung vorhanden?")
            self._connect_btn.setChecked(False)
            return

        try:
            self._bus = can.Bus(
                channel=interface, interface='socketcan',
                fd=fd, receive_own_messages=loopback)
        except can.CanError as e:
            QMessageBox.warning(self, "Verbindungsfehler", str(e))
            self._connect_btn.setChecked(False)
            return

        self._rx_thread = CanReceiveThread(self._bus, self)
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

        # Bus-State-Ueberwachung starten
        self._bus_state_timer.start()
        self._check_bus_state()

        for w in (self._iface_combo, self._bitrate_combo,
                  self._fd_check, self._fd_bitrate_combo,
                  self._loopback_check):
            w.setEnabled(False)

    def _disconnect_device(self):
        self._bus_state_timer.stop()
        self._bus_state_label.setText("")
        self._stop_periodic()

        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
            self._rx_thread = None

        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
            self._bus = None

        interface = self._iface_combo.currentText().strip()
        try:
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                capture_output=True, timeout=5)
        except Exception:
            pass

        self._status_indicator.setText("\u25cf Getrennt")
        self._status_indicator.setStyleSheet("color: #F44336; font-weight: bold;")
        self._connect_btn.setText("Verbinden")
        self._send_btn.setEnabled(False)
        self._per_start.setEnabled(False)
        self._per_stop.setEnabled(False)

        for w in (self._iface_combo, self._bitrate_combo,
                  self._fd_check, self._loopback_check):
            w.setEnabled(True)
        self._fd_bitrate_combo.setEnabled(self._fd_check.isChecked())

    # ═══════════════════════════════════════════════════════════════════
    # Senden
    # ═══════════════════════════════════════════════════════════════════

    def _parse_can_id(self):
        text = self._tx_id.text().strip()
        try:
            return int(text, 16) if text.lower().startswith('0x') else int(text)
        except ValueError:
            return None

    def _parse_hex_data(self):
        text = self._tx_data.text().strip().replace(' ', '')
        if len(text) % 2 != 0:
            text = text[:-1]
        try:
            return bytes.fromhex(text) if text else b''
        except ValueError:
            return None

    def _send_frame(self) -> bool:
        """Sendet einen CAN-Frame. Gibt True bei Erfolg zurueck."""
        if self._bus is None:
            return False

        can_id = self._parse_can_id()
        if can_id is None:
            QMessageBox.warning(self, "Fehler", "Ungueltige CAN-ID")
            return False
        data = self._parse_hex_data()
        if data is None:
            QMessageBox.warning(self, "Fehler", "Ungueltige Hex-Daten")
            return False

        msg = can.Message(
            arbitration_id=can_id, data=data,
            is_extended_id=self._tx_ext.isChecked(),
            is_fd=self._fd_check.isChecked())

        try:
            self._bus.send(msg)
            self._tx_count += 1
            self._tx_reference[can_id] = bytes(data)

            elapsed = time.time() - (self._start_time or time.time())
            self._add_tx_row(can_id, data, elapsed)
            self._update_counters()
            self._consecutive_errors = 0
            return True
        except Exception as e:
            _log.error("CAN-Senden: %s", e)
            return False

    def _start_periodic(self):
        if self._bus is None:
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
        self._per_start.setEnabled(self._bus is not None)
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
        """Empfangener Frame → Signal fuer bus_queues[0]."""
        self._rx_count += 1

        ts = frame['timestamp']
        if self._start_time and ts > 1e9:
            ts = ts - self._start_time

        can_id = frame['can_id']
        is_ext = frame.get('is_extended', False)
        data = frame.get('data', b'')
        data_hex = ' '.join(f'{b:02X}' for b in data)
        id_str = f"0x{can_id:08X}" if is_ext else f"0x{can_id:03X}"
        channel = self._iface_combo.currentText()

        fd_info = "CAN FD" if frame.get('is_fd') else "CAN"
        msg_name = self.dbc_lookup(can_id)

        # Differenz-Check
        if can_id in self._tx_reference:
            tx_data = self._tx_reference[can_id]
            if data != tx_data:
                tx_hex = ' '.join(f'{b:02X}' for b in tx_data)
                fd_info += f" [DIFF vs TX: {tx_hex}]"

        # Bus-Queue Format: (zeit, kanal, id, name, dlc, daten, info)
        row_tuple = (
            f"{ts:.6f}",
            channel,
            id_str,
            msg_name,
            str(frame.get('dlc', len(data))),
            data_hex,
            f"PCAN {fd_info}",
        )
        self.frame_for_bus_queue.emit(row_tuple)
        self._update_counters()

        # Signal-Plot fuettern
        if self._plot_widget is not None and self._dbc is not None:
            self._plot_widget.feed_can_frame(ts, can_id, data)

    def _on_rx_error(self, error):
        _log.error("PCAN RX-Fehler: %s", error)

    # ═══════════════════════════════════════════════════════════════════
    # TX-Tabelle
    # ═══════════════════════════════════════════════════════════════════

    def _add_tx_row(self, can_id: int, data: bytes, elapsed: float):
        row = (self._tx_count - 1) % 30

        is_ext = self._tx_ext.isChecked()
        id_str = f"0x{can_id:08X}" if is_ext else f"0x{can_id:03X}"
        data_hex = ' '.join(f'{b:02X}' for b in data)
        channel = self._iface_combo.currentText()

        cells = [
            str(self._tx_count), f"{elapsed:.6f}", channel,
            id_str, "", str(len(data)), data_hex, "TX"
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
        """Berechnet TX/RX/PLP-Rate mit EMA-Glaettung (alpha=0.3)."""
        now = time.monotonic()
        elapsed = now - self._last_rate_time if self._last_rate_time > 0 else 1.0
        self._last_rate_time = now
        if elapsed <= 0:
            elapsed = 1.0
        alpha = 0.3  # ~3s effektives Fenster

        # TX-Rate (EMA)
        tx_delta = self._tx_count - self._last_tx_count
        self._last_tx_count = self._tx_count
        instant_tx = tx_delta / elapsed
        self._smoothed_tx_rate = alpha * instant_tx + (1 - alpha) * self._smoothed_tx_rate
        self._tx_rate_label.setText(f"{round(self._smoothed_tx_rate)} paket/s")

        # CAN-Rate (EMA): bus_row_counters zaehlt einzelne CAN-Frames
        if self._bus_row_counters is not None:
            current = self._bus_row_counters[self._bus_index]
            can_delta = current - self._last_bus_row_count
            self._last_bus_row_count = current
        else:
            can_delta = self._rx_count - self._last_rx_count
            self._last_rx_count = self._rx_count
        instant_can = can_delta / elapsed
        self._smoothed_can_rate = alpha * instant_can + (1 - alpha) * self._smoothed_can_rate

        # PLP-Rate (EMA)
        plp_delta = 0
        if hasattr(self, "_plp_counters") and self._plp_counters is not None:
            current_plp = self._plp_counters[self._plp_index]
            plp_delta = current_plp - self._last_plp_count
            self._last_plp_count = current_plp
        instant_plp = plp_delta / elapsed
        self._smoothed_plp_rate = alpha * instant_plp + (1 - alpha) * self._smoothed_plp_rate

        # CAN-Rate auf TX-Rate begrenzen (kann nicht mehr empfangen als gesendet)
        can_display = round(self._smoothed_can_rate)
        tx_display = round(self._smoothed_tx_rate)
        if tx_display > 0 and can_display > tx_display:
            can_display = tx_display
        self._can_rate_label.setText(f"CAN: {can_display} Frames/s")

        plp_display = round(self._smoothed_plp_rate)
        if can_display > 0 and plp_display < 1:
            plp_display = 1
        self._plp_rate_label.setText(f"PLP: {plp_display} Pkt/s")

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
    # Bus-State-Ueberwachung (ERROR-ACTIVE / ERROR-PASSIVE / BUS-OFF)
    # ═══════════════════════════════════════════════════════════════════

    _BUS_STATE_RE = re.compile(
        r'can\s+state\s+([\w-]+)\s+\(berr-counter\s+tx\s+(\d+)\s+rx\s+(\d+)\)')
    _ERROR_STATS_RE = re.compile(
        r're-started\s+bus-errors\s+arbit-lost\s+error-warn\s+'
        r'error-pass\s+bus-off\s+'
        r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)')

    _STATE_STYLES = {
        'ERROR-ACTIVE':  ('ERROR-ACTIVE',  '#4CAF50'),  # Gruen
        'ERROR-WARNING': ('ERROR-WARNING',  '#FF9800'),  # Orange
        'ERROR-PASSIVE': ('ERROR-PASSIVE',  '#F44336'),  # Rot
        'BUS-OFF':       ('BUS-OFF',        '#D50000'),  # Dunkelrot
        'STOPPED':       ('STOPPED',        '#888888'),  # Grau
    }

    def _check_bus_state(self):
        """Liest CAN-Bus-State und Fehlerstatistiken via ip -statistics."""
        interface = self._iface_combo.currentText().strip()
        if not interface:
            return
        try:
            result = subprocess.run(
                ['ip', '-statistics', '-details', 'link', 'show', interface],
                capture_output=True, text=True, timeout=2)
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        # ── Bus-State parsen ──
        m = self._BUS_STATE_RE.search(output)
        if not m:
            return
        state, tec, rec = m.group(1), int(m.group(2)), int(m.group(3))

        # State-Label aktualisieren (nur bei Aenderung)
        state_key = f"{state}:{tec}:{rec}"
        if state_key != self._last_bus_state:
            self._last_bus_state = state_key

            label_text, color = self._STATE_STYLES.get(
                state, (state, '#B3E5FC'))
            if tec > 0 or rec > 0:
                label_text += f"  TEC:{tec} REC:{rec}"

            self._bus_state_label.setText(label_text)
            self._bus_state_label.setStyleSheet(
                f"color: {color}; font-size: 10px; font-weight: bold;"
                " background: transparent;")

        # ── Error-Statistiken parsen ──
        em = self._ERROR_STATS_RE.search(output)
        if em:
            restarts = int(em.group(1))
            bus_err = int(em.group(2))
            arbit = int(em.group(3))
            err_warn = int(em.group(4))
            err_pass = int(em.group(5))
            bus_off = int(em.group(6))

            # Nur relevante Zaehler anzeigen (> 0)
            parts = []
            if bus_err > 0:
                parts.append(f"Bit-Err:{bus_err}")
            if arbit > 0:
                parts.append(f"Arbit:{arbit}")
            if err_warn > 0:
                parts.append(f"Warn:{err_warn}")
            if err_pass > 0:
                parts.append(f"Passiv:{err_pass}")
            if bus_off > 0:
                parts.append(f"BusOff:{bus_off}")
            if restarts > 0:
                parts.append(f"Restart:{restarts}")

            err_text = "  ".join(parts) if parts else ""
            if err_text != self._last_error_stats:
                self._last_error_stats = err_text
                self._bus_error_label.setText(err_text)
                if bus_off > 0 or err_pass > 0:
                    self._bus_error_label.setStyleSheet(
                        "color: #FF8A80; font-weight: bold; font-size: 10px;"
                        " background: transparent;")
                elif parts:
                    self._bus_error_label.setStyleSheet(
                        "color: #FFD54F; font-weight: bold; font-size: 10px;"
                        " background: transparent;")

        # ── Bei ERROR-PASSIVE oder BUS-OFF reagieren ──
        if state in ('ERROR-PASSIVE', 'BUS-OFF'):
            # Zyklisches Senden stoppen
            if self._periodic_timer:
                self._stop_periodic()
                self._per_label.setText(f"GESTOPPT: {state}")
                pass  # State wird in _bus_state_label angezeigt
                _log.warning(
                    "Zyklisches Senden gestoppt: CAN-Bus %s (TEC=%d, REC=%d)",
                    state, tec, rec)

            # BUS-OFF: automatische Wiederherstellung versuchen
            if state == 'BUS-OFF':
                self._attempt_bus_recovery(interface)
        else:
            # Bei Erholung: Recovery-Zaehler zuruecksetzen
            self._recovery_attempts = 0

    def _attempt_bus_recovery(self, interface: str):
        """Versucht CAN-Bus nach BUS-OFF automatisch wiederherzustellen."""
        if self._recovery_attempts >= self._max_recovery_attempts:
            if self._recovery_attempts == self._max_recovery_attempts:
                self._recovery_attempts += 1  # Nur 1x loggen
                _log.error(
                    "BUS-OFF Recovery aufgegeben nach %d Versuchen"
                    " — manueller Neustart noetig",
                    self._max_recovery_attempts)
                self._bus_state_label.setText(
                    "BUS-OFF — Recovery fehlgeschlagen!")
            return

        self._recovery_attempts += 1
        _log.warning(
            "BUS-OFF Recovery Versuch %d/%d fuer %s",
            self._recovery_attempts, self._max_recovery_attempts, interface)

        self._bus_state_label.setText(
            f"BUS-OFF — Recovery {self._recovery_attempts}/"
            f"{self._max_recovery_attempts}...")

        # RX-Thread und Bus stoppen
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
            self._rx_thread = None
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
            self._bus = None

        # Interface neu starten
        try:
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                capture_output=True, timeout=3)
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'up'],
                capture_output=True, timeout=3)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            _log.error("Recovery ip-link: %s", e)
            return

        # python-can Bus neu oeffnen
        fd = self._fd_check.isChecked()
        loopback = self._loopback_check.isChecked()
        try:
            self._bus = can.Bus(
                channel=interface, interface='socketcan',
                fd=fd, receive_own_messages=loopback)
            self._rx_thread = CanReceiveThread(self._bus, self)
            self._rx_thread.frame_received.connect(self._on_frame_received)
            self._rx_thread.error_occurred.connect(self._on_rx_error)
            self._rx_thread.start()
            _log.info("BUS-OFF Recovery erfolgreich: %s", interface)
            self._bus_state_label.setText("Recovery OK — pruefe...")
            self._last_bus_state = ""  # Erzwingt Neuauswertung
        except Exception as e:
            _log.error("BUS-OFF Recovery Bus-Open: %s", e)
            self._bus_state_label.setText(f"Recovery fehlgeschlagen: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # Bereinigung
    # ═══════════════════════════════════════════════════════════════════

    def cleanup(self):
        """Muss von aussen aufgerufen werden (z.B. closeEvent)."""
        self._rate_timer.stop()
        self._bus_state_timer.stop()
        self._stop_periodic()
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
