"""PCAN-USB Pro FD Konfiguration und TX/RX-Ansicht fuer Live CAN.

Integriert sich in die bestehende Live CAN Seite des WiresharkPanels:
- Faltbares Konfigurationspanel (Schnittstelle, Bitrate, CAN-FD, Loopback)
- TX-Bereich: Sende-Konfiguration + Sende-Historie
- Bestehendes CAN-TableView als RX-Bereich (mit BusTableModel + FilterHeader)
- Empfangene PCAN-Frames werden in bus_queues eingespeist
"""

import logging
import math
import os
import random
import re
import socket
import struct
import subprocess
import time
from collections import deque
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QStackedWidget,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QCheckBox, QHeaderView,
    QGroupBox, QMessageBox, QTableView, QFileDialog, QInputDialog,
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
_SIM_ROW_PURPLE = QColor("#F3E5F5")  # Material Purple-50 (淡紫)
_SIM_ROW_WHITE = QColor("#FFFFFF")


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
        self._schedule_widget = None  # ScheduleTableWidget
        self._stats_widget = None  # BusStatisticsWidget
        self._diag_widget = None   # UDSDiagWidget
        self._gateway_widget = None  # GatewayConfigWidget
        self._gateway_engine = None  # GatewayEngine
        self._auto_widget = None   # ScriptEditorWidget
        self._auto_api = None      # AutomationAPI
        self._dbc_name = ''  # geladener DBC-Dateiname
        self._last_tx_count = 0
        self._last_rx_count = 0
        self._bus_row_counters = None  # Wird von WiresharkPanel gesetzt
        self._bus_index = 0
        self._last_bus_row_count = 0
        self._prev_sysfs_rx = 0  # PLP-Paketrate aus sysfs
        self._smoothed_can_rate = 0.0  # EMA-geglaettete CAN-Rate
        self._smoothed_plp_rate = 0.0  # EMA-geglaettete PLP-Rate
        self._smoothed_plp_can_rate = 0.0  # EMA: CAN-Frames aus PLP
        self._smoothed_pcan_rate = 0.0  # EMA: PCAN direkte Frames
        self._smoothed_tx_rate = 0.0   # EMA-geglaettete TX-Rate
        self._last_plp_can_count = 0
        self._last_rate_time = 0.0     # Zeitstempel fuer Rate-Berechnung
        self._current_sub_tab = 0
        self._sim_frame_count = 0
        self._sim_start_time = time.time()
        self._sim_periodic_timer: Optional[QTimer] = None
        self._sim_dbc = None
        self._sim_dbc_name = ''
        self._sim_seq_index = 0
        self._sim_pattern_counter = 0
        self._sim_send_enabled = False
        self._sim_send_socket: Optional[socket.socket] = None
        self._sim_send_counter = 0
        self._sim_last_frame_count = 0
        self._smoothed_sim_rate = 0.0
        # RTT: can_id → deque of (send_time, sim_frame_nr)
        self._sim_rtt_sent: Dict[int, deque] = {}
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Sub-Tab-Leiste (PCAN USB PRO FD | CAN Simulator) ──
        layout.addWidget(self._create_sub_tab_bar())

        # ── Stacked Widget fuer Config+TX Bereich ──
        self._sub_content_stack = QStackedWidget()

        # Page 0: PCAN USB PRO FD (Config + TX)
        pcan_page = QWidget()
        pcan_layout = QVBoxLayout(pcan_page)
        pcan_layout.setContentsMargins(0, 0, 0, 0)
        pcan_layout.setSpacing(0)
        pcan_config = self._create_pcan_config()
        pcan_config.setStyleSheet(NATIVE_COMBO_CSS)
        pcan_layout.addWidget(pcan_config)
        pcan_layout.addWidget(self._create_tx_section())
        self._sub_content_stack.addWidget(pcan_page)

        # Page 1: CAN Simulator
        self._sub_content_stack.addWidget(self._create_simulator_page())

        # ── Splitter: Config+TX (stacked) + RX (shared) ──
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #d0d0d8; height: 3px; }")
        splitter.addWidget(self._sub_content_stack)

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

    def _create_pcan_config(self) -> QWidget:
        """Erstellt den PCAN USB PRO FD Konfigurationsinhalt."""
        config = QWidget()
        clayout = QVBoxLayout(config)
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
            "QPushButton { background-color: #4CAF50; color: white;"
            "  font-weight: bold; }"
            "QPushButton:disabled { background-color: #a0a0a0;"
            "  color: #666666; }")
        self._per_start.clicked.connect(self._start_periodic)
        self._per_start.setEnabled(False)
        self._per_start.setMinimumWidth(80)

        self._per_stop = QPushButton("\u2b1b Stop")
        self._per_stop.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white;"
            "  font-weight: bold; }"
            "QPushButton:disabled { background-color: #a0a0a0;"
            "  color: #666666; }")
        self._per_stop.clicked.connect(self._stop_periodic)
        self._per_stop.setEnabled(False)
        self._per_stop.setMinimumWidth(80)

        # _bus_btn_layout fuer add_bus_button() (falls benoetigt)
        self._bus_btn_layout = QHBoxLayout()
        self._bus_btn_layout.setSpacing(4)
        row1.addLayout(self._bus_btn_layout)

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

        # Schedule Table Toggle
        self._schedule_btn = QPushButton('Schedule')
        self._schedule_btn.setCheckable(True)
        self._schedule_btn.setMinimumWidth(80)
        self._schedule_btn.setToolTip('Multi-Frame zyklisches Senden')
        self._schedule_btn.toggled.connect(self._toggle_schedule)
        row1.addWidget(self._schedule_btn)

        # Statistics Toggle
        self._stats_btn = QPushButton('Statistik')
        self._stats_btn.setCheckable(True)
        self._stats_btn.setMinimumWidth(80)
        self._stats_btn.setToolTip('Echtzeit TX/RX Statistik-Diagramm')
        self._stats_btn.toggled.connect(self._toggle_stats)
        row1.addWidget(self._stats_btn)

        # UDS Diagnose Toggle
        self._diag_btn = QPushButton('UDS')
        self._diag_btn.setCheckable(True)
        self._diag_btn.setMinimumWidth(60)
        self._diag_btn.setToolTip('UDS Diagnose-Panel (ISO 14229)')
        self._diag_btn.toggled.connect(self._toggle_diag)
        row1.addWidget(self._diag_btn)

        # Gateway Toggle
        self._gateway_btn = QPushButton('Gateway')
        self._gateway_btn.setCheckable(True)
        self._gateway_btn.setMinimumWidth(70)
        self._gateway_btn.setToolTip('Cross-Bus Routing')
        self._gateway_btn.toggled.connect(self._toggle_gateway)
        row1.addWidget(self._gateway_btn)

        # Automation Toggle
        self._auto_btn = QPushButton('Script')
        self._auto_btn.setCheckable(True)
        self._auto_btn.setMinimumWidth(60)
        self._auto_btn.setToolTip('Python Automation Script')
        self._auto_btn.toggled.connect(self._toggle_automation)
        row1.addWidget(self._auto_btn)

        row1.addStretch()

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
        return config

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
        self._plp_can_counters = plp_can_counters
        self._plp_index = index
        self._last_plp_count = 0
        self._last_plp_can_count = 0

    def set_source_iface_ref(self, ifaces: list, protos: list, index: int):
        """Setzt Referenz auf bus_source_ifaces/protos fuer RX-Header."""
        self._source_ifaces = ifaces
        self._source_protos = protos
        self._source_iface_index = index
        self._last_shown_src = ""

    # ── Schedule Table ──

    def _toggle_schedule(self, checked: bool):
        if checked:
            if self._schedule_widget is None:
                from ui.widgets.schedule_table_widget import ScheduleTableWidget
                self._schedule_widget = ScheduleTableWidget('CAN', self)
                self._schedule_widget.frame_to_send.connect(
                    self._on_schedule_send)
                # Nach TX-Tabelle einfuegen
                self.layout().insertWidget(2, self._schedule_widget)
            self._schedule_widget.show()
        else:
            if self._schedule_widget is not None:
                self._schedule_widget.hide()

    def _on_schedule_send(self, frame_dict: dict):
        """Sendet einen Frame aus der Schedule-Tabelle."""
        if self._bus is None:
            return
        try:
            import can
            msg = can.Message(
                arbitration_id=frame_dict['frame_id'],
                data=frame_dict['data'],
                is_extended_id=frame_dict['frame_id'] > 0x7FF,
            )
            self._bus.send(msg)
            self._tx_count += 1
            if self._stats_widget:
                self._stats_widget.record_tx()
        except Exception as e:
            _log.error("Schedule-Senden: %s", e)

    # ── Statistics ──

    def _toggle_stats(self, checked: bool):
        if checked:
            if self._stats_widget is None:
                from ui.widgets.bus_statistics_widget import BusStatisticsWidget
                self._stats_widget = BusStatisticsWidget('CAN', self)
                self.layout().insertWidget(3, self._stats_widget)
            self._stats_widget.show()
        else:
            if self._stats_widget is not None:
                self._stats_widget.hide()

    # ── UDS Diagnose ──

    def _toggle_diag(self, checked: bool):
        if checked:
            if self._diag_widget is None:
                from ui.widgets.uds_diag_widget import UDSDiagWidget
                self._diag_widget = UDSDiagWidget(self)
                self._diag_widget.send_can_frame.connect(
                    self._on_diag_send)
                self.layout().insertWidget(4, self._diag_widget)
            self._diag_widget.show()
        else:
            if self._diag_widget is not None:
                self._diag_widget.hide()

    def _on_diag_send(self, frame_id: int, data: bytes):
        """Sendet einen CAN-Frame aus dem UDS-Panel."""
        if self._bus is None:
            return
        try:
            import can
            msg = can.Message(
                arbitration_id=frame_id,
                data=data,
                is_extended_id=frame_id > 0x7FF,
            )
            self._bus.send(msg)
            self._tx_count += 1
            if self._stats_widget:
                self._stats_widget.record_tx()
        except Exception as e:
            _log.error("UDS-Senden: %s", e)

    # ── Gateway ──

    def _toggle_gateway(self, checked: bool):
        if checked:
            if self._gateway_engine is None:
                from core.gateway_engine import GatewayEngine
                self._gateway_engine = GatewayEngine(self)
                # CAN-Sender registrieren
                self._gateway_engine.register_sender(
                    'CAN', self._gateway_can_send)
            if self._gateway_widget is None:
                from ui.widgets.gateway_config_widget import GatewayConfigWidget
                self._gateway_widget = GatewayConfigWidget(
                    self._gateway_engine, self)
                self.layout().insertWidget(5, self._gateway_widget)
            self._gateway_widget.show()
        else:
            if self._gateway_widget is not None:
                self._gateway_widget.hide()

    def _gateway_can_send(self, frame_id: int, data: bytes, dlc: int):
        """Gateway-Sender fuer CAN."""
        if self._bus is None:
            return
        import can
        msg = can.Message(
            arbitration_id=frame_id,
            data=data[:dlc],
            is_extended_id=frame_id > 0x7FF,
        )
        self._bus.send(msg)

    # ── Automation ──

    def _toggle_automation(self, checked: bool):
        if checked:
            if self._auto_api is None:
                from core.automation_api import AutomationAPI
                self._auto_api = AutomationAPI()
                self._auto_api.set_can_sender(self._auto_can_send)
            if self._auto_widget is None:
                from ui.widgets.script_editor_widget import ScriptEditorWidget
                self._auto_widget = ScriptEditorWidget(self._auto_api, self)
                self.layout().insertWidget(6, self._auto_widget)
            self._auto_widget.show()
        else:
            if self._auto_widget is not None:
                self._auto_widget.hide()

    def _auto_can_send(self, frame_id: int, data: bytes) -> bool:
        """CAN-Sender fuer Automation API."""
        if self._bus is None:
            return False
        try:
            import can
            msg = can.Message(
                arbitration_id=frame_id,
                data=data,
                is_extended_id=frame_id > 0x7FF,
            )
            self._bus.send(msg)
            self._tx_count += 1
            return True
        except Exception:
            return False

    # ── TX Templates ──

    def _save_tx_template(self):
        """Speichert die aktuelle TX-Konfiguration als Template."""
        from core.tx_template_manager import save_template
        name, ok = QInputDialog.getText(
            self, "Template speichern", "Template-Name:")
        if not ok or not name.strip():
            return
        frame = {
            'id': self._tx_id.text(),
            'dlc': self._tx_dlc.value(),
            'data': self._tx_data_edit.text(),
            'extended': self._tx_extended.isChecked(),
            'fd': self._fd_check.isChecked(),
            'cycle_ms': self._per_interval.value(),
        }
        path = save_template('CAN', name.strip(), [frame])
        QMessageBox.information(
            self, "Template", f"Template gespeichert:\n{path}")

    def _load_tx_template(self):
        """Laedt ein TX-Template und fuellt die Eingabefelder."""
        from core.tx_template_manager import list_templates
        templates = list_templates('CAN')
        if not templates:
            QMessageBox.information(
                self, "Template", "Keine CAN-Templates vorhanden.")
            return
        names = [t['name'] for t in templates]
        name, ok = QInputDialog.getItem(
            self, "Template laden", "Template:", names, 0, False)
        if not ok:
            return
        idx = names.index(name)
        tpl = templates[idx]
        frames = tpl.get('frames', [])
        if not frames:
            return
        f = frames[0]
        self._tx_id.setText(f.get('id', '0x123'))
        self._tx_dlc.setValue(f.get('dlc', 8))
        self._tx_data_edit.setText(f.get('data', ''))
        self._tx_extended.setChecked(f.get('extended', False))
        self._fd_check.setChecked(f.get('fd', False))
        self._per_interval.setValue(f.get('cycle_ms', 100))

    # ── Sub-Tab-Leiste + Umschaltung ─────────────────────────────────────

    def _create_sub_tab_bar(self) -> QWidget:
        """Erstellt die Sub-Tab-Leiste (PCAN USB PRO FD | CAN Simulator)."""
        bar = QWidget()
        bar.setStyleSheet('background-color: #e8e8f0;')
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(4, 2, 4, 0)
        bar_layout.setSpacing(2)

        _ACTIVE = (
            'QPushButton { background: #ffffff; color: #0d47a1;'
            '  border: 1px solid #c0c0c8; border-bottom: 2px solid #ffffff;'
            '  border-radius: 4px 4px 0 0; padding: 4px 12px;'
            '  font-size: 11px; font-weight: bold; }')
        _INACTIVE = (
            'QPushButton { background: #dcdce5; color: #555555;'
            '  border: 1px solid #c0c0c8; border-bottom: none;'
            '  border-radius: 4px 4px 0 0; padding: 4px 12px; font-size: 11px; }'
            'QPushButton:hover { background: #d0d0dc; color: #333333; }')

        self._sub_tab_buttons: list = []
        self._sub_tab_active_style = _ACTIVE
        self._sub_tab_inactive_style = _INACTIVE

        _sub_tabs = [
            '\U0001f50c PCAN USB PRO FD',
            '\U0001f916 CAN Simulator',
        ]
        for i, label in enumerate(_sub_tabs):
            btn = QPushButton(label)
            btn.setMinimumWidth(160)
            btn.setStyleSheet(_ACTIVE if i == 0 else _INACTIVE)
            btn.clicked.connect(
                lambda checked, idx=i: self._switch_sub_tab(idx))
            bar_layout.addWidget(btn)
            self._sub_tab_buttons.append(btn)

        bar_layout.addStretch()
        return bar

    def _switch_sub_tab(self, index: int):
        """Wechselt zwischen PCAN USB PRO FD und CAN Simulator."""
        if index == self._current_sub_tab:
            return
        self._current_sub_tab = index
        for i, btn in enumerate(self._sub_tab_buttons):
            btn.setStyleSheet(
                self._sub_tab_active_style if i == index
                else self._sub_tab_inactive_style)
        self._sub_content_stack.setCurrentIndex(index)

    # ── CAN Simulator Seite ───────────────────────────────────────────────

    def _create_simulator_page(self) -> QWidget:
        """Erstellt die CAN Simulator Seite (softwaregenerierte CAN-Frames)."""
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        # ── Konfigurations-Bereich ──
        config = QWidget()
        clayout = QVBoxLayout(config)
        clayout.setContentsMargins(8, 4, 8, 4)
        clayout.setSpacing(4)

        # Zeile 0: DBC + Pattern + Protokoll + Netzwerk + senden + RTT
        row0 = QHBoxLayout()
        row0.setSpacing(6)

        self._sim_dbc_btn = QPushButton('DBC...')
        self._sim_dbc_btn.setToolTip(
            'DBC-Datei laden fuer Signal-Encoding')
        self._sim_dbc_btn.setMinimumWidth(65)
        self._sim_dbc_btn.clicked.connect(self._sim_load_dbc)
        row0.addWidget(self._sim_dbc_btn)

        row0.addWidget(QLabel("Pattern:"))
        self._sim_pattern_combo = QComboBox()
        self._sim_pattern_combo.addItems(
            ["Statisch", "Inkrement", "Zufall", "Sinus"])
        self._sim_pattern_combo.setMinimumWidth(110)
        self._sim_pattern_combo.setToolTip(
            "Statisch: Daten unveraendert\n"
            "Inkrement: Byte-Zaehler +1 pro Frame\n"
            "Zufall: Zufaellige Daten pro Frame\n"
            "Sinus: Sinuswelle im ersten Byte")
        row0.addWidget(self._sim_pattern_combo)

        row0.addWidget(QLabel("Protokoll:"))
        self._sim_proto_combo = QComboBox()
        self._sim_proto_combo.addItems(["PLP", "TECMP", "CMP"])
        self._sim_proto_combo.setMinimumWidth(90)
        self._sim_proto_combo.setToolTip(
            "PLP: EtherType 0x2090 (ViGEM Logger)\n"
            "TECMP: EtherType 0x99FE (Technica CM)\n"
            "CMP: EtherType 0x99FE (ASAM Standard)")
        row0.addWidget(self._sim_proto_combo)

        row0.addWidget(QLabel("Netzwerk:"))
        self._sim_iface_combo = QComboBox()
        self._sim_iface_combo.setMinimumWidth(120)
        self._sim_iface_combo.setToolTip(
            "Netzwerk-Interface fuer Raw-Ethernet Senden")
        self._sim_refresh_ifaces()
        row0.addWidget(self._sim_iface_combo)

        self._sim_echo_filter = QCheckBox("Echo-Filter")
        self._sim_echo_filter.setChecked(True)
        self._sim_echo_filter.setToolTip(
            "Eigene Frames in RX herausfiltern\n"
            "(Src MAC = lokales Interface)")
        row0.addWidget(self._sim_echo_filter)

        self._sim_rtt_label = QLabel("RTT: ---")
        self._sim_rtt_label.setStyleSheet(
            "color: #6A1B9A; font-weight: bold; font-size: 11px;")
        self._sim_rtt_label.setMinimumWidth(120)
        row0.addWidget(self._sim_rtt_label)

        row0.addStretch()
        clayout.addLayout(row0)

        # Zeile 1: Modus + Intervall + Anzahl
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        row1.addWidget(QLabel("Modus:"))
        self._sim_mode_combo = QComboBox()
        self._sim_mode_combo.addItems(
            ["Einzeln", "Zyklisch", "Sequenz"])
        self._sim_mode_combo.setMinimumWidth(100)
        self._sim_mode_combo.currentIndexChanged.connect(
            self._sim_on_mode_changed)
        row1.addWidget(self._sim_mode_combo)

        row1.addWidget(QLabel("Intervall:"))
        self._sim_interval = QSpinBox()
        self._sim_interval.setRange(1, 60000)
        self._sim_interval.setValue(100)
        self._sim_interval.setSuffix(" ms")
        self._sim_interval.setMaximumWidth(100)
        row1.addWidget(self._sim_interval)

        self._sim_count_spin = QSpinBox()
        self._sim_count_spin.setRange(0, 1000000)
        self._sim_count_spin.setValue(0)
        self._sim_count_spin.setSpecialValueText("Endlos")
        self._sim_count_spin.setPrefix("Anzahl: ")
        self._sim_count_spin.setMinimumWidth(120)
        row1.addWidget(self._sim_count_spin)

        row1.addStretch()
        clayout.addLayout(row1)

        # Zeile 2: Frame-Definition
        row2 = QHBoxLayout()
        row2.setSpacing(6)

        row2.addWidget(QLabel("Device ID:"))
        self._sim_device_id = QLineEdit("0xFFFF")
        self._sim_device_id.setMaximumWidth(70)
        self._sim_device_id.setFont(_MONO)
        self._sim_device_id.setToolTip(
            "PLP/TECMP/CMP Geraete-ID\n"
            "(wird im Protokoll-Header verwendet)")
        row2.addWidget(self._sim_device_id)

        row2.addWidget(QLabel("CAN ID:"))
        self._sim_id = QLineEdit("0x100")
        self._sim_id.setMaximumWidth(90)
        self._sim_id.setFont(_MONO)
        row2.addWidget(self._sim_id)

        self._sim_ext = QCheckBox("Ext")
        row2.addWidget(self._sim_ext)

        row2.addWidget(QLabel("DLC:"))
        self._sim_dlc = QSpinBox()
        self._sim_dlc.setRange(0, 8)
        self._sim_dlc.setValue(8)
        self._sim_dlc.setMaximumWidth(55)
        row2.addWidget(self._sim_dlc)

        row2.addWidget(QLabel("Daten:"))
        self._sim_data = QLineEdit("00 00 00 00 00 00 00 00")
        self._sim_data.setFont(_MONO)
        self._sim_data.setPlaceholderText("00 11 22 33 ...")
        row2.addWidget(self._sim_data, 1)

        self._sim_send_btn = QPushButton("\u25b6 Generieren")
        self._sim_send_btn.setMinimumWidth(110)
        self._sim_send_btn.clicked.connect(self._sim_generate_single)
        row2.addWidget(self._sim_send_btn)

        self._sim_start_btn = QPushButton("\u25b6 Start")
        self._sim_start_btn.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white;"
            "  font-weight: bold; }"
            "QPushButton:disabled { background-color: #a0a0a0;"
            "  color: #666666; }")
        self._sim_start_btn.setMinimumWidth(80)
        self._sim_start_btn.clicked.connect(self._sim_start_periodic)
        row2.addWidget(self._sim_start_btn)

        self._sim_stop_btn = QPushButton("\u2b1b Stop")
        self._sim_stop_btn.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white;"
            "  font-weight: bold; }"
            "QPushButton:disabled { background-color: #a0a0a0;"
            "  color: #666666; }")
        self._sim_stop_btn.setMinimumWidth(80)
        self._sim_stop_btn.setEnabled(False)
        self._sim_stop_btn.clicked.connect(self._sim_stop_periodic)
        row2.addWidget(self._sim_stop_btn)

        clayout.addLayout(row2)
        page_layout.addWidget(config)

        # ── Sequenz-Tabelle (nur bei Modus "Sequenz" sichtbar) ──
        self._sim_seq_widget = QWidget()
        seq_layout = QVBoxLayout(self._sim_seq_widget)
        seq_layout.setContentsMargins(8, 0, 8, 4)
        seq_layout.setSpacing(2)

        seq_btn_row = QHBoxLayout()
        seq_btn_row.setSpacing(4)

        seq_add_btn = QPushButton("+ Zeile")
        seq_add_btn.setMinimumWidth(80)
        seq_add_btn.clicked.connect(self._sim_add_seq_row)
        seq_btn_row.addWidget(seq_add_btn)

        seq_rem_btn = QPushButton("\u2212 Zeile")
        seq_rem_btn.setMinimumWidth(80)
        seq_rem_btn.clicked.connect(self._sim_remove_seq_row)
        seq_btn_row.addWidget(seq_rem_btn)

        seq_btn_row.addStretch()
        seq_layout.addLayout(seq_btn_row)

        self._sim_seq_table = QTableWidget()
        self._sim_seq_table.setColumnCount(4)
        self._sim_seq_table.setHorizontalHeaderLabels(
            ["ID", "DLC", "Daten", "Delay (ms)"])
        self._sim_seq_table.setFont(_MONO)
        self._sim_seq_table.verticalHeader().setVisible(False)
        self._sim_seq_table.verticalHeader().setDefaultSectionSize(22)
        self._sim_seq_table.setMaximumHeight(150)
        sh_seq = self._sim_seq_table.horizontalHeader()
        sh_seq.setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self._sim_seq_table.setColumnWidth(0, 80)
        self._sim_seq_table.setColumnWidth(1, 50)
        self._sim_seq_table.setColumnWidth(3, 90)
        self._sim_seq_table.setStyleSheet(
            "QTableWidget { background-color: #ffffff; color: #1a1a1a;"
            "  gridline-color: #ce93d8; }"
            "QHeaderView::section { background: #f5f5f7; color: #0d0d17;"
            "  padding: 4px 6px; border: none;"
            "  border-right: 1px solid #d0d0d8;"
            "  border-bottom: 1px solid #333333;"
            "  font-weight: bold; }")
        self._sim_add_seq_row()  # eine Startzeile
        seq_layout.addWidget(self._sim_seq_table)

        self._sim_seq_widget.hide()
        page_layout.addWidget(self._sim_seq_widget)

        # ── Simulator TX Header ──
        sim_header = QWidget()
        sim_header.setFixedHeight(22)
        sim_header.setStyleSheet(
            "background-color: #6A1B9A; color: white;")
        sim_h = QHBoxLayout(sim_header)
        sim_h.setContentsMargins(4, 0, 4, 0)
        sim_h.setSpacing(8)

        sim_title = QLabel("SIM \u2014 Simulierte CAN-Frames")
        sim_title.setStyleSheet(
            "font-weight: bold; font-size: 11px;"
            " background: transparent;")
        sim_h.addWidget(sim_title)
        sim_h.addStretch()

        self._sim_count_label = QLabel("0 Frames")
        self._sim_count_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        sim_h.addWidget(self._sim_count_label)

        self._sim_rate_label = QLabel("0 Frames/s")
        self._sim_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        sim_h.addWidget(self._sim_rate_label)

        self._sim_clear_btn = QPushButton("\U0001f5d1 Leeren")
        self._sim_clear_btn.setStyleSheet(
            "QPushButton { background: transparent; color: #FFD54F;"
            "  border: 1px solid #FFD54F; border-radius: 3px;"
            "  padding: 1px 8px; font-size: 10px; font-weight: bold; }"
            "QPushButton:hover { background: rgba(255,213,79,0.2); }")
        self._sim_clear_btn.setFixedHeight(18)
        self._sim_clear_btn.setMinimumWidth(70)
        self._sim_clear_btn.clicked.connect(self._sim_clear_table)
        sim_h.addWidget(self._sim_clear_btn)

        page_layout.addWidget(sim_header)

        # ── Simulator Tabelle (淡紫/白 交替行) ──
        self._sim_table = QTableWidget()
        self._sim_table.setColumnCount(7)
        self._sim_table.setHorizontalHeaderLabels(
            ["Nr.", "Zeit", "ID", "Name", "DLC", "Daten", "Info"])
        self._sim_table.setFont(QFont("Consolas", 9))
        self._sim_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._sim_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._sim_table.verticalHeader().setVisible(False)
        self._sim_table.verticalHeader().setDefaultSectionSize(22)
        self._sim_table.setShowGrid(True)
        self._sim_table.setStyleSheet(
            "QTableWidget { background-color: #ffffff; color: #1a1a1a;"
            "  gridline-color: #ce93d8; }"
            "QTableWidget::item:selected { background-color: #6A1B9A;"
            "  color: #ffffff; }"
            "QHeaderView::section { background: #f5f5f7; color: #0d0d17;"
            "  padding: 4px 6px; border: none;"
            "  border-right: 1px solid #d0d0d8;"
            "  border-bottom: 1px solid #333333;"
            "  font-weight: bold; }")
        sh = self._sim_table.horizontalHeader()
        _sim_widths = [60, 120, 80, 100, 50, 400, 100]
        for col, w in enumerate(_sim_widths):
            sh.setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
                if col == 5 else QHeaderView.ResizeMode.Interactive)
            self._sim_table.setColumnWidth(col, w)

        # 预填充30行空行 (淡紫/白 交替背景)
        for r in range(30):
            self._sim_table.insertRow(r)
            bg = _SIM_ROW_PURPLE if r % 2 == 0 else _SIM_ROW_WHITE
            for c in range(7):
                item = QTableWidgetItem("")
                item.setBackground(bg)
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignCenter
                    | Qt.AlignmentFlag.AlignVCenter)
                self._sim_table.setItem(r, c, item)

        page_layout.addWidget(self._sim_table, 1)
        return page

    def _sim_apply_pattern(self, data_bytes: bytes, dlc: int) -> bytes:
        """Wendet das gewaehlte Daten-Pattern auf die Basisdaten an."""
        pattern = self._sim_pattern_combo.currentText()
        if pattern == "Statisch":
            return data_bytes
        if pattern == "Inkrement":
            self._sim_pattern_counter += 1
            c = self._sim_pattern_counter & 0xFF
            return bytes([(b + c) & 0xFF for b in data_bytes])
        if pattern == "Zufall":
            return bytes(random.randint(0, 255) for _ in range(dlc))
        if pattern == "Sinus":
            self._sim_pattern_counter += 1
            # Sinuswelle (Periode 256 Frames) im ersten Byte
            val = int(127.5 + 127.5 * math.sin(
                2 * math.pi * self._sim_pattern_counter / 256))
            out = bytearray(data_bytes)
            if out:
                out[0] = val & 0xFF
            return bytes(out)
        return data_bytes

    def _sim_dbc_lookup(self, can_id: int) -> str:
        """Sucht den Nachrichtennamen in der Simulator-DBC."""
        dbc = self._sim_dbc or self._dbc
        if dbc is None:
            return ""
        try:
            msg = dbc.get_message_by_frame_id(can_id)
            return msg.name if msg else ""
        except Exception:
            return ""

    def _sim_generate_single(self):
        """Einzelner Frame: Socket oeffnen, senden, schliessen."""
        self._sim_open_socket()
        self._sim_generate_frame()
        self._sim_close_socket()

    def _sim_generate_frame(self):
        """Generiert einen CAN-Frame und zeigt ihn in der SIM-Tabelle."""
        try:
            id_text = self._sim_id.text().strip()
            can_id = int(id_text, 16) if id_text.lower().startswith(
                '0x') else int(id_text)
            dlc = self._sim_dlc.value()
            raw = self._sim_data.text().strip().replace(' ', '')
            data_bytes = bytes.fromhex(raw)[:dlc]
        except (ValueError, Exception) as e:
            _log.error("CAN Simulator Eingabefehler: %s", e)
            return

        # Pattern anwenden
        data_bytes = self._sim_apply_pattern(data_bytes, dlc)
        is_ext = self._sim_ext.isChecked()

        # An Netzwerk senden (PLP/TECMP/CMP)
        self._sim_send_frame(can_id, dlc, data_bytes, is_ext)

        self._sim_frame_count += 1
        elapsed = time.time() - self._sim_start_time
        data_str = ' '.join(f'{b:02X}' for b in data_bytes)
        name = self._sim_dbc_lookup(can_id)
        proto = self._sim_proto_combo.currentText() if \
            self._sim_send_enabled else ""
        cca_tag = f"SIM \u2192 {proto}" if self._sim_send_enabled \
            else "SIM"

        # 写入 SIM 表格 (循环覆盖预填充行, 淡紫/白 交替)
        row = (self._sim_frame_count - 1) % 30
        bg = _SIM_ROW_PURPLE if row % 2 == 0 else _SIM_ROW_WHITE

        cells = [
            str(self._sim_frame_count),
            f"{elapsed:.6f}",
            f"0x{can_id:03X}",
            name,
            str(len(data_bytes)),
            data_str,
            cca_tag,
        ]
        for col, text in enumerate(cells):
            item = self._sim_table.item(row, col)
            if item is not None:
                item.setText(text)
            else:
                item = QTableWidgetItem(text)
                item.setFont(_MONO)
                item.setBackground(bg)
                self._sim_table.setItem(row, col, item)
        self._sim_count_label.setText(f"{self._sim_frame_count} Frames")

        # Anzahl-Limit pruefen (zyklischer Modus)
        limit = self._sim_count_spin.value()
        if limit > 0 and self._sim_frame_count >= limit:
            self._sim_stop_periodic()

    def _sim_generate_seq_frame(self):
        """Generiert den naechsten Frame aus der Sequenz-Tabelle."""
        table = self._sim_seq_table
        if table.rowCount() == 0:
            self._sim_stop_periodic()
            return

        r = self._sim_seq_index % table.rowCount()
        try:
            id_text = (table.item(r, 0).text().strip()
                       if table.item(r, 0) else "0x100")
            can_id = int(id_text, 16) if id_text.lower().startswith(
                '0x') else int(id_text)
            dlc = int(table.item(r, 1).text().strip()
                      if table.item(r, 1) else "8")
            raw = (table.item(r, 2).text().strip().replace(' ', '')
                   if table.item(r, 2) else "00" * dlc)
            data_bytes = bytes.fromhex(raw)[:dlc]
            delay = int(table.item(r, 3).text().strip()
                        if table.item(r, 3) else "100")
        except (ValueError, Exception) as e:
            _log.error("Sequenz Zeile %d Fehler: %s", r, e)
            self._sim_seq_index += 1
            return

        # Pattern anwenden
        data_bytes = self._sim_apply_pattern(data_bytes, dlc)

        # An Netzwerk senden (PLP/TECMP/CMP)
        self._sim_send_frame(can_id, dlc, data_bytes)

        self._sim_frame_count += 1
        elapsed = time.time() - self._sim_start_time
        data_str = ' '.join(f'{b:02X}' for b in data_bytes)
        name = self._sim_dbc_lookup(can_id)
        proto = self._sim_proto_combo.currentText() if \
            self._sim_send_enabled else ""
        cca_tag = f"SEQ[{r}] \u2192 {proto}" if self._sim_send_enabled \
            else f"SEQ[{r}]"

        # 写入 SIM 表格 (循环覆盖, 淡紫/白 交替)
        sim_row = (self._sim_frame_count - 1) % 30
        bg = _SIM_ROW_PURPLE if sim_row % 2 == 0 else _SIM_ROW_WHITE

        cells = [
            str(self._sim_frame_count),
            f"{elapsed:.6f}",
            f"0x{can_id:03X}",
            name,
            str(len(data_bytes)),
            data_str,
            cca_tag,
        ]
        for col, text in enumerate(cells):
            item = self._sim_table.item(sim_row, col)
            if item is not None:
                item.setText(text)
            else:
                item = QTableWidgetItem(text)
                item.setFont(_MONO)
                item.setBackground(bg)
                self._sim_table.setItem(sim_row, col, item)
        self._sim_count_label.setText(f"{self._sim_frame_count} Frames")

        self._sim_seq_index += 1

        # Naechsten Delay setzen
        if self._sim_periodic_timer:
            next_r = self._sim_seq_index % table.rowCount()
            try:
                next_delay = int(table.item(next_r, 3).text().strip()
                                 if table.item(next_r, 3) else "100")
            except (ValueError, Exception):
                next_delay = 100
            self._sim_periodic_timer.setInterval(next_delay)

        # Anzahl-Limit pruefen
        limit = self._sim_count_spin.value()
        if limit > 0 and self._sim_frame_count >= limit:
            self._sim_stop_periodic()

    def _sim_start_periodic(self):
        """Startet periodische Frame-Generierung + Raw-Socket Senden."""
        self._sim_pattern_counter = 0
        mode = self._sim_mode_combo.currentText()

        # Raw-Socket oeffnen fuer Netzwerk-Senden
        self._sim_open_socket()

        self._sim_periodic_timer = QTimer(self)

        if mode == "Sequenz":
            self._sim_seq_index = 0
            self._sim_periodic_timer.setInterval(
                self._sim_interval.value())
            self._sim_periodic_timer.timeout.connect(
                self._sim_generate_seq_frame)
        else:
            self._sim_periodic_timer.setInterval(
                self._sim_interval.value())
            self._sim_periodic_timer.timeout.connect(
                self._sim_generate_frame)

        self._sim_periodic_timer.start()
        self._sim_start_btn.setEnabled(False)
        self._sim_stop_btn.setEnabled(True)
        self._sim_send_btn.setEnabled(False)

    def _sim_stop_periodic(self):
        """Stoppt periodische Frame-Generierung + schliesst Socket."""
        if self._sim_periodic_timer:
            self._sim_periodic_timer.stop()
            self._sim_periodic_timer = None
        # Raw-Socket schliessen
        self._sim_close_socket()
        self._sim_start_btn.setEnabled(True)
        self._sim_stop_btn.setEnabled(False)
        self._sim_send_btn.setEnabled(True)

    def _sim_load_dbc(self):
        """DBC-Datei laden fuer CAN Simulator Signal-Encoding."""
        path, _ = QFileDialog.getOpenFileName(
            self, "DBC-Datei laden (Simulator)", "",
            "DBC-Dateien (*.dbc);;Alle Dateien (*)")
        if not path:
            return
        try:
            import cantools
            self._sim_dbc = cantools.database.load_file(path)
            self._sim_dbc_name = path.rsplit('/', 1)[-1].rsplit(
                '\\', 1)[-1]
            self._sim_dbc_btn.setText(f'DBC \u2714')
            self._sim_dbc_btn.setToolTip(
                f'{self._sim_dbc_name}\n'
                f'{len(self._sim_dbc.messages)} Nachrichten\n'
                'Erneut klicken zum Wechseln')
            _log.info("Simulator DBC: %s (%d Nachrichten)",
                       self._sim_dbc_name,
                       len(self._sim_dbc.messages))
        except Exception as e:
            QMessageBox.warning(
                self, "DBC-Fehler", f"Fehler: {e}")

    def _sim_on_mode_changed(self, index: int):
        """Zeigt/versteckt Sequenz-Tabelle je nach Modus."""
        is_seq = (index == 2)  # "Sequenz"
        self._sim_seq_widget.setVisible(is_seq)

    def _sim_add_seq_row(self):
        """Fuegt eine Zeile zur Sequenz-Tabelle hinzu."""
        table = self._sim_seq_table
        r = table.rowCount()
        table.insertRow(r)
        table.setItem(r, 0, QTableWidgetItem("0x100"))
        table.setItem(r, 1, QTableWidgetItem("8"))
        table.setItem(r, 2, QTableWidgetItem(
            "00 00 00 00 00 00 00 00"))
        table.setItem(r, 3, QTableWidgetItem("100"))

    def _sim_remove_seq_row(self):
        """Entfernt die ausgewaehlte Zeile aus der Sequenz-Tabelle."""
        table = self._sim_seq_table
        row = table.currentRow()
        if row >= 0:
            table.removeRow(row)
        elif table.rowCount() > 0:
            table.removeRow(table.rowCount() - 1)

    def _sim_clear_table(self):
        """Leert die SIM-Tabelle und setzt Zaehler zurueck."""
        self._sim_frame_count = 0
        self._sim_pattern_counter = 0
        self._sim_last_frame_count = 0
        self._smoothed_sim_rate = 0.0
        self._sim_start_time = time.time()
        self._sim_rtt_sent.clear()
        self._sim_count_label.setText("0 Frames")
        self._sim_rate_label.setText("0 Frames/s")
        self._sim_rtt_label.setText("RTT: ---")
        # Alle Zellen leeren, Hintergrundfarben beibehalten
        for r in range(self._sim_table.rowCount()):
            for c in range(self._sim_table.columnCount()):
                item = self._sim_table.item(r, c)
                if item is not None:
                    item.setText("")

    # ── Netzwerk-Interfaces ──────────────────────────────────────────

    def _sim_refresh_ifaces(self):
        """Liest verfuegbare Netzwerk-Interfaces aus /sys/class/net."""
        self._sim_iface_combo.clear()
        try:
            ifaces = sorted(os.listdir('/sys/class/net/'))
            self._sim_iface_combo.addItems(ifaces)
        except OSError:
            self._sim_iface_combo.addItem("eth0")

    @staticmethod
    def _get_mac(iface: str) -> bytes:
        """Liest die MAC-Adresse eines Interfaces."""
        try:
            with open(f'/sys/class/net/{iface}/address') as f:
                mac_str = f.read().strip()
            return bytes.fromhex(mac_str.replace(':', ''))
        except Exception:
            return b'\x00\x00\x00\x00\x00\x00'

    # ── Senden (PLP/TECMP/CMP ueber AF_PACKET) ───────────────────────

    @staticmethod
    def _sim_dbg(msg: str):
        """Debug-Log in /tmp/sim_debug.log."""
        try:
            with open('/tmp/sim_debug.log', 'a') as f:
                f.write(f"{time.time():.3f} {msg}\n")
        except Exception:
            pass

    def _sim_open_socket(self):
        """Oeffnet Raw-Socket fuer das gewaehlte Interface/Protokoll."""
        iface = self._sim_iface_combo.currentText()
        proto = self._sim_proto_combo.currentText()
        ether = 0x2090 if proto == "PLP" else 0x99FE
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW,
                socket.htons(ether))
            sock.bind((iface, 0))
            self._sim_send_socket = sock
            self._sim_send_enabled = True
            self._sim_dbg(f"Socket OK: {iface} 0x{ether:04X}")
        except PermissionError:
            _log.error("Raw-Socket benoetigt Root-Rechte")
            QMessageBox.warning(
                self, "Berechtigung",
                "Raw-Socket benoetigt Root-Rechte.\n"
                "Starten Sie LiveCapture mit sudo.")
            self._sim_send_enabled = False
        except Exception as e:
            _log.error("Socket-Fehler: %s", e)
            self._sim_send_enabled = False

    def _sim_close_socket(self):
        """Schliesst den Raw-Socket."""
        self._sim_send_enabled = False
        if self._sim_send_socket:
            self._sim_send_socket.close()
            self._sim_send_socket = None

    def _sim_get_device_id(self) -> int:
        """Liest die Device ID aus dem Eingabefeld."""
        try:
            text = self._sim_device_id.text().strip()
            return int(text, 16) if text.lower().startswith(
                '0x') else int(text)
        except (ValueError, Exception):
            return 0xFFFF

    def _sim_build_can_payload(self, can_id: int, dlc: int,
                               data_bytes: bytes,
                               is_ext: bool = False) -> bytes:
        """Baut den CAN-Frame Payload (gemeinsam fuer alle Protokolle)."""
        id_raw = can_id | (0x80000000 if is_ext else 0)
        return struct.pack('>IB', id_raw, dlc) + data_bytes[:dlc]

    def _sim_build_plp_tecmp(self, can_payload: bytes) -> bytes:
        """Baut PLP/TECMP Protokoll-Daten (Header 12B + Entry 16B + Payload).

        PLP (0x2090) und TECMP (0x99FE) verwenden das gleiche Format.
        """
        self._sim_send_counter = (self._sim_send_counter + 1) & 0xFFFF
        device_id = self._sim_get_device_id()
        version = 3
        msg_type = 0x0A     # Replay Data
        data_type = 0x0002  # CAN Data
        header = struct.pack('>HH BB HI',
                             device_id, self._sim_send_counter,
                             version, msg_type,
                             data_type, 0)
        ts_ns = int(time.time() * 1_000_000_000) & 0xFFFFFFFFFFFFFFFF
        entry = struct.pack('>HH QH H',
                            0x0000, 0x0001, ts_ns,
                            len(can_payload), 0x0000)
        return header + entry + can_payload

    def _sim_build_cmp(self, can_payload: bytes) -> bytes:
        """Baut ASAM CMP Protokoll-Daten (Header 8B + Payload).

        Header: CmpVersion(1) + Reserved(1) + DeviceId(2)
                + MessageType(1) + StreamId(1) + SeqCounter(2)
        """
        self._sim_send_counter = (self._sim_send_counter + 1) & 0xFFFF
        device_id = self._sim_get_device_id()
        header = struct.pack('>BB HB BH',
                             0x01,    # CmpVersion
                             0x00,    # Reserved
                             device_id,
                             0x01,    # MessageType = Data
                             0x01,    # StreamId
                             self._sim_send_counter)
        return header + can_payload

    def _sim_send_frame(self, can_id: int, dlc: int,
                        data_bytes: bytes, is_ext: bool = False):
        """Sendet einen CAN-Frame als PLP/TECMP/CMP ueber Raw-Ethernet."""
        if not self._sim_send_enabled or not self._sim_send_socket:
            return
        self._sim_dbg(f"send_frame CAN=0x{can_id:03X} dlc={dlc}")
        try:
            proto = self._sim_proto_combo.currentText()
            iface = self._sim_iface_combo.currentText()
            can_payload = self._sim_build_can_payload(
                can_id, dlc, data_bytes, is_ext)

            if proto == "CMP":
                ether_type = 0x99FE
                payload = self._sim_build_cmp(can_payload)
            else:  # PLP oder TECMP
                ether_type = 0x2090 if proto == "PLP" else 0x99FE
                payload = self._sim_build_plp_tecmp(can_payload)

            # Ethernet-Frame: dst(6) + src(6) + EtherType(2) + payload
            src_mac = self._get_mac(iface)
            dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
            eth_frame = (dst_mac + src_mac
                         + struct.pack('>H', ether_type)
                         + payload)

            sent = self._sim_send_socket.send(eth_frame)
            print(f"[SIM] TX: {sent}B via {iface} "
                  f"{proto}(0x{ether_type:04X}) "
                  f"CAN=0x{can_id:03X}", flush=True)

            # RTT: Zeitstempel merken
            send_time = time.monotonic()
            if can_id not in self._sim_rtt_sent:
                self._sim_rtt_sent[can_id] = deque(maxlen=100)
            self._sim_rtt_sent[can_id].append(
                (send_time, self._sim_frame_count))
        except Exception as e:
            _log.error("Netzwerk-Senden: %s", e)

    # ── Echo-Filter ────────────────────────────────────────────────────

    def should_filter_echo(self, src_mac_bytes: bytes) -> bool:
        """Prueft ob ein Frame mit dieser Src-MAC gefiltert werden soll.

        Gibt True zurueck wenn Echo-Filter aktiv UND src_mac
        dem aktuellen Sende-Interface entspricht.
        """
        if not self._sim_echo_filter.isChecked():
            return False
        if not self._sim_send_enabled:
            return False
        iface = self._sim_iface_combo.currentText()
        our_mac = self._get_mac(iface)
        return src_mac_bytes == our_mac

    # ── RTT Tracking ──────────────────────────────────────────────────

    def on_rx_can_frame(self, can_id: int):
        """Wird von WiresharkPanel aufgerufen wenn ein CAN-Frame
        im RX-Stream (bus_queues[0]) ankommt.
        Prueft ob dieser Frame einem gesendeten SIM-Frame entspricht
        und berechnet die RTT.
        """
        q = self._sim_rtt_sent.get(can_id)
        if not q:
            return
        send_time, frame_nr = q.popleft()
        rtt_ms = (time.monotonic() - send_time) * 1000
        self._sim_rtt_label.setText(
            f"RTT: {rtt_ms:.1f} ms (#{frame_nr})")

        # Info-Spalte im SIM-Table aktualisieren
        sim_row = (frame_nr - 1) % 30
        item = self._sim_table.item(sim_row, 6)
        if item is not None:
            item.setText(f"RTT {rtt_ms:.1f}ms")

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
        # Doppelklick auf Header → Spalte umschalten:
        # 1. Klick: an Inhalt anpassen, 2. Klick: Standardbreite
        self._tx_default_widths = dict(enumerate(_widths))
        self._tx_col_toggled = {}

        def _toggle_tx_col(col):
            if self._tx_col_toggled.get(col, False):
                if col in self._tx_default_widths:
                    if col == 6:  # Daten-Spalte: Stretch wiederherstellen
                        h.setSectionResizeMode(
                            col, QHeaderView.ResizeMode.Stretch)
                    self._tx_table.setColumnWidth(
                        col, self._tx_default_widths[col])
                self._tx_col_toggled[col] = False
            else:
                if col == 6:  # Daten-Spalte: Stretch aufheben
                    h.setSectionResizeMode(
                        col, QHeaderView.ResizeMode.Interactive)
                self._tx_table.resizeColumnToContents(col)
                self._tx_col_toggled[col] = True

        h.sectionDoubleClicked.connect(_toggle_tx_col)

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
            if self._stats_widget:
                self._stats_widget.record_tx()

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
        if self._stats_widget:
            self._stats_widget.record_rx()
        # UDS ISO-TP Reassembly
        if self._diag_widget is not None:
            self._diag_widget.on_can_frame_received(
                frame['can_id'], frame.get('data', b''))
        # Gateway-Routing
        if self._gateway_engine is not None:
            self._gateway_engine.on_frame_received(
                'CAN', frame['can_id'],
                frame.get('data', b''), frame.get('dlc', 0))
        # Automation API
        if self._auto_api is not None:
            self._auto_api.on_frame_received(
                'CAN', frame['can_id'],
                frame.get('data', b''), frame.get('dlc', 0))

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
        tx_display = round(self._smoothed_tx_rate)

        # ── PLP-Rate + CAN-from-PLP ──
        plp_delta = 0
        plp_can_delta = 0
        if hasattr(self, "_plp_counters") and self._plp_counters is not None:
            idx = self._plp_index
            current_plp = self._plp_counters[idx]
            plp_delta = current_plp - self._last_plp_count
            self._last_plp_count = current_plp
        if hasattr(self, "_plp_can_counters") and self._plp_can_counters is not None:
            idx = self._plp_index
            current_plp_can = self._plp_can_counters[idx]
            plp_can_delta = current_plp_can - self._last_plp_can_count
            self._last_plp_can_count = current_plp_can

        instant_plp = plp_delta / elapsed
        instant_plp_can = plp_can_delta / elapsed
        self._smoothed_plp_rate = alpha * instant_plp + (1 - alpha) * self._smoothed_plp_rate
        self._smoothed_plp_can_rate = alpha * instant_plp_can + (1 - alpha) * getattr(
            self, '_smoothed_plp_can_rate', 0.0)

        # Durchschnittliche CAN-Frames pro PLP-Paket
        plp_display = round(self._smoothed_plp_rate)
        plp_can_display = round(self._smoothed_plp_can_rate)
        if plp_can_display > 0 and plp_display < 1:
            plp_display = 1
        avg_can_per_plp = round(plp_can_display / plp_display) if plp_display > 0 else 0

        # ── PCAN-Rate (direkt von SocketCAN, nicht aus PLP) ──
        pcan_delta = self._rx_count - self._last_rx_count
        self._last_rx_count = self._rx_count
        instant_pcan = pcan_delta / elapsed
        self._smoothed_pcan_rate = alpha * instant_pcan + (1 - alpha) * getattr(
            self, '_smoothed_pcan_rate', 0.0)
        pcan_display = round(self._smoothed_pcan_rate)

        # ── CAN-Gesamt = PLP-CAN + PCAN ──
        can_total = plp_can_display + pcan_display

        # ── Anzeige aktualisieren ──
        # TX-Rate
        self._tx_rate_label.setText(f"{tx_display} paket/s")

        # PLP: Pkt/s (×N CAN/Pkt)
        if plp_display > 0:
            self._plp_rate_label.setText(
                f"PLP: {plp_display} Pkt/s (\u00d7{avg_can_per_plp} CAN/Pkt)")
        else:
            self._plp_rate_label.setText("PLP: 0 Pkt/s")

        # CAN: N(PLP) + N(PCAN) = N F/s | TX: N F/s
        self._can_rate_label.setText(
            f"CAN: {plp_can_display}(PLP) + {pcan_display}(PCAN)"
            f" = {can_total} F/s")

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

        # ── SIM-Rate (Simulator Frames/s) ──
        sim_delta = self._sim_frame_count - self._sim_last_frame_count
        self._sim_last_frame_count = self._sim_frame_count
        instant_sim = sim_delta / elapsed
        self._smoothed_sim_rate = (
            alpha * instant_sim
            + (1 - alpha) * self._smoothed_sim_rate)
        sim_display = round(self._smoothed_sim_rate)
        self._sim_rate_label.setText(f"{sim_display} Frames/s")

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
        if self._schedule_widget is not None:
            self._schedule_widget.cleanup()
        if self._stats_widget is not None:
            self._stats_widget.cleanup()
        if self._diag_widget is not None:
            self._diag_widget.cleanup()
        if self._gateway_widget is not None:
            self._gateway_widget.cleanup()
        if self._auto_widget is not None:
            self._auto_widget.cleanup()
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
