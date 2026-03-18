"""PCAN-USB Pro FD Konfiguration und TX/RX-Ansicht fuer Live CAN.

Integriert sich in die bestehende Live CAN Seite des WiresharkPanels:
- Faltbares Konfigurationspanel (Schnittstelle, Bitrate, CAN-FD, Loopback)
- TX-Bereich: Sende-Konfiguration + Sende-Historie
- Bestehendes CAN-TableView als RX-Bereich (mit BusTableModel + FilterHeader)
- Empfangene PCAN-Frames werden in bus_queues eingespeist
"""

import logging
import subprocess
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QCheckBox, QHeaderView,
    QGroupBox, QMessageBox, QTableView,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

from core.platform import get_can_interfaces

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

# ── Dark-Theme-Style (passend zu Live Capture) ─────────────────────────
_DARK_WIDGET = (
    "QWidget { background-color: #1a1a2e; color: #bbbbdd; }"
    "QLabel { background: transparent; border: none; color: #bbbbdd; }"
)
_DARK_INPUT = (
    "QLineEdit, QComboBox, QSpinBox {"
    "  background: #2a2a3e; color: #ddddee; border: 1px solid #444;"
    "  border-radius: 3px; padding: 2px 4px; }"
)
_DARK_BTN = (
    "QPushButton { background: #2a2a3e; color: #ddd; border: 1px solid #444;"
    "  border-radius: 3px; padding: 4px 10px; }"
    "QPushButton:hover { background: #3a3a5e; color: #fff; }"
    "QPushButton:disabled { color: #555; }"
)
_DARK_BTN_CONNECT = (
    "QPushButton { background: #2a2a3e; color: #ddd; border: 1px solid #444;"
    "  border-radius: 3px; padding: 4px 10px; }"
    "QPushButton:hover { background: #3a3a5e; color: #fff; }"
    "QPushButton:checked { background: #2E7D32; color: white; font-weight: bold; }"
)
_DARK_TABLE = (
    "QTableWidget { background-color: #1e1e30; color: #ddddee;"
    "  alternate-background-color: #252540; gridline-color: #3a3a5e; }"
    "QTableWidget::item:selected { background-color: #1565c0; color: #ffffff; }"
    "QHeaderView::section { background-color: #2a2a3e; color: #bbbbdd;"
    "  border: 1px solid #3a3a5e; padding: 2px 4px; }"
)
_TX_ROW_BG = QColor(30, 40, 70)  # Dunkles Blau fuer TX


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
            "QSplitter::handle { background: #3a3a5e; height: 3px; }")

        # TX-Bereich
        splitter.addWidget(self._create_tx_section())

        # RX-Bereich: bestehendes CAN-TableView
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        rx_header = QLabel("  RX \u2014 Empfangene Daten (TECMP + PCAN)")
        rx_header.setFixedHeight(22)
        rx_header.setStyleSheet(
            "background-color: #2E7D32; color: white;"
            "font-weight: bold; font-size: 11px; padding-left: 4px;")
        rx_layout.addWidget(rx_header)
        rx_layout.addWidget(self._existing_table)
        splitter.addWidget(rx_wrapper)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

    # ── Konfigurationspanel ─────────────────────────────────────────────

    def _create_config_panel(self) -> QWidget:
        group = QGroupBox("PCAN-USB Pro FD")
        group.setCheckable(True)
        group.setChecked(True)
        group.setStyleSheet(
            "QGroupBox { color: #4FC3F7; border: 1px solid #3a3a5e;"
            "  border-radius: 4px; margin-top: 6px; padding-top: 12px;"
            "  background-color: #1a1a2e; font-weight: bold; }"
            "QGroupBox::title { subcontrol-origin: margin;"
            "  subcontrol-position: top left; padding: 0 4px; }"
            + _DARK_INPUT + _DARK_BTN)

        clayout = QVBoxLayout(group)
        clayout.setContentsMargins(8, 4, 8, 4)
        clayout.setSpacing(4)

        # Zeile 1: Schnittstelle + Bitrate
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        lbl_if = QLabel("Schnittstelle:")
        lbl_if.setStyleSheet("color: #bbbbdd; background: transparent;")
        row1.addWidget(lbl_if)
        self._iface_combo = QComboBox()
        self._iface_combo.setEditable(True)
        self._iface_combo.addItems(get_can_interfaces())
        self._iface_combo.setMinimumWidth(90)
        row1.addWidget(self._iface_combo)

        lbl_br = QLabel("Bitrate:")
        lbl_br.setStyleSheet("color: #bbbbdd; background: transparent;")
        row1.addWidget(lbl_br)
        self._bitrate_combo = QComboBox()
        self._bitrate_combo.setEditable(True)
        self._bitrate_combo.addItems(_BITRATES)
        self._bitrate_combo.setCurrentText("500000")
        self._bitrate_combo.setMinimumWidth(90)
        row1.addWidget(self._bitrate_combo)

        self._fd_check = QCheckBox("CAN-FD")
        self._fd_check.setStyleSheet("color: #bbbbdd;")
        self._fd_check.toggled.connect(self._on_fd_toggled)
        row1.addWidget(self._fd_check)

        lbl_fdbr = QLabel("FD-Bitrate:")
        lbl_fdbr.setStyleSheet("color: #bbbbdd; background: transparent;")
        row1.addWidget(lbl_fdbr)
        self._fd_bitrate_combo = QComboBox()
        self._fd_bitrate_combo.setEditable(True)
        self._fd_bitrate_combo.addItems(_FD_BITRATES)
        self._fd_bitrate_combo.setCurrentText("2000000")
        self._fd_bitrate_combo.setEnabled(False)
        self._fd_bitrate_combo.setMinimumWidth(90)
        row1.addWidget(self._fd_bitrate_combo)

        self._loopback_check = QCheckBox("Loopback")
        self._loopback_check.setStyleSheet("color: #bbbbdd;")
        row1.addWidget(self._loopback_check)

        row1.addStretch()

        # Verbinden-Button
        self._connect_btn = QPushButton("Verbinden")
        self._connect_btn.setCheckable(True)
        self._connect_btn.setStyleSheet(_DARK_BTN_CONNECT)
        self._connect_btn.setMinimumWidth(110)
        self._connect_btn.toggled.connect(self._on_connect_toggled)
        row1.addWidget(self._connect_btn)

        self._status_indicator = QLabel("\u25cf Getrennt")
        self._status_indicator.setStyleSheet(
            "color: #F44336; font-weight: bold; background: transparent;")
        row1.addWidget(self._status_indicator)

        clayout.addLayout(row1)
        return group

    # ── TX-Bereich ──────────────────────────────────────────────────────

    def _create_tx_section(self) -> QWidget:
        widget = QWidget()
        widget.setStyleSheet(_DARK_WIDGET + _DARK_INPUT + _DARK_BTN)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # TX-Header
        tx_header = QLabel("  TX \u2014 Sende-Konfiguration")
        tx_header.setFixedHeight(22)
        tx_header.setStyleSheet(
            "background-color: #1565C0; color: white;"
            "font-weight: bold; font-size: 11px; padding-left: 4px;")
        layout.addWidget(tx_header)

        # Sende-Zeile
        send_row = QHBoxLayout()
        send_row.setContentsMargins(4, 4, 4, 2)
        send_row.setSpacing(4)

        send_row.addWidget(QLabel("ID:"))
        self._tx_id = QLineEdit("0x123")
        self._tx_id.setMaximumWidth(90)
        self._tx_id.setFont(_MONO)
        send_row.addWidget(self._tx_id)

        self._tx_ext = QCheckBox("Ext")
        self._tx_ext.setStyleSheet("color: #bbbbdd;")
        send_row.addWidget(self._tx_ext)

        send_row.addWidget(QLabel("DLC:"))
        self._tx_dlc = QSpinBox()
        self._tx_dlc.setRange(0, 8)
        self._tx_dlc.setValue(8)
        self._tx_dlc.setMaximumWidth(55)
        send_row.addWidget(self._tx_dlc)

        send_row.addWidget(QLabel("Daten:"))
        self._tx_data = QLineEdit("00 11 22 33 44 55 66 77")
        self._tx_data.setFont(_MONO)
        self._tx_data.setPlaceholderText("00 11 22 33 ...")
        send_row.addWidget(self._tx_data, 1)

        self._send_btn = QPushButton("\u25b6 Senden")
        self._send_btn.clicked.connect(self._send_frame)
        self._send_btn.setEnabled(False)
        self._send_btn.setMinimumWidth(90)
        send_row.addWidget(self._send_btn)

        layout.addLayout(send_row)

        # Periodisches Senden
        per_row = QHBoxLayout()
        per_row.setContentsMargins(4, 0, 4, 2)
        per_row.setSpacing(4)
        per_row.addWidget(QLabel("Zyklisch:"))
        self._per_interval = QSpinBox()
        self._per_interval.setRange(1, 60000)
        self._per_interval.setValue(100)
        self._per_interval.setSuffix(" ms")
        self._per_interval.setMaximumWidth(110)
        per_row.addWidget(self._per_interval)

        self._per_start = QPushButton("Start")
        self._per_start.clicked.connect(self._start_periodic)
        self._per_start.setEnabled(False)
        per_row.addWidget(self._per_start)

        self._per_stop = QPushButton("Stopp")
        self._per_stop.clicked.connect(self._stop_periodic)
        self._per_stop.setEnabled(False)
        per_row.addWidget(self._per_stop)

        self._per_label = QLabel("")
        self._per_label.setStyleSheet("color: #4FC3F7; background: transparent;")
        per_row.addWidget(self._per_label)

        self._tx_status = QLabel("TX: 0 | RX: 0")
        self._tx_status.setStyleSheet(
            "color: #888; background: transparent; margin-left: 12px;")
        per_row.addWidget(self._tx_status)

        per_row.addStretch()
        layout.addLayout(per_row)

        # TX-Tabelle
        self._tx_table = QTableWidget()
        self._tx_table.setColumnCount(8)
        self._tx_table.setHorizontalHeaderLabels(_TX_HEADERS)
        self._tx_table.setStyleSheet(_DARK_TABLE)
        self._tx_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._tx_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tx_table.setFont(_MONO)
        self._tx_table.verticalHeader().setVisible(False)
        self._tx_table.verticalHeader().setDefaultSectionSize(22)
        h = self._tx_table.horizontalHeader()
        _widths = [50, 120, 60, 80, 100, 40, 200, 100]
        for col, w in enumerate(_widths):
            h.setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
                if col in (4, 6) else QHeaderView.ResizeMode.Interactive)
            self._tx_table.setColumnWidth(col, w)
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
        self._status_indicator.setStyleSheet(
            "color: #4CAF50; font-weight: bold; background: transparent;")
        self._connect_btn.setText("Trennen")
        self._send_btn.setEnabled(True)
        self._per_start.setEnabled(True)

        for w in (self._iface_combo, self._bitrate_combo,
                  self._fd_check, self._fd_bitrate_combo,
                  self._loopback_check):
            w.setEnabled(False)

    def _disconnect_device(self):
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
        self._status_indicator.setStyleSheet(
            "color: #F44336; font-weight: bold; background: transparent;")
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

    def _send_frame(self):
        if self._bus is None:
            return

        can_id = self._parse_can_id()
        if can_id is None:
            QMessageBox.warning(self, "Fehler", "Ungueltige CAN-ID")
            return
        data = self._parse_hex_data()
        if data is None:
            QMessageBox.warning(self, "Fehler", "Ungueltige Hex-Daten")
            return

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
        except Exception as e:
            _log.error("CAN-Senden: %s", e)

    def _start_periodic(self):
        if self._bus is None:
            return
        self._stop_periodic()
        self._periodic_count = 0
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
        self._send_frame()
        self._periodic_count += 1
        self._per_label.setText(f"Aktiv: {self._periodic_count}")

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
            "",  # Name (DBC)
            str(frame.get('dlc', len(data))),
            data_hex,
            f"PCAN {fd_info}",
        )
        self.frame_for_bus_queue.emit(row_tuple)
        self._update_counters()

    def _on_rx_error(self, error):
        _log.error("PCAN RX-Fehler: %s", error)

    # ═══════════════════════════════════════════════════════════════════
    # TX-Tabelle
    # ═══════════════════════════════════════════════════════════════════

    def _add_tx_row(self, can_id: int, data: bytes, elapsed: float):
        table = self._tx_table
        row = table.rowCount()
        table.insertRow(row)
        if row >= _MAX_TX_ROWS:
            table.removeRow(0)
            row -= 1

        is_ext = self._tx_ext.isChecked()
        id_str = f"0x{can_id:08X}" if is_ext else f"0x{can_id:03X}"
        data_hex = ' '.join(f'{b:02X}' for b in data)
        channel = self._iface_combo.currentText()

        cells = [
            str(self._tx_count), f"{elapsed:.6f}", channel,
            id_str, "", str(len(data)), data_hex, "TX"
        ]
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setBackground(_TX_ROW_BG)
            if col in (1, 3, 6):
                item.setFont(_MONO)
            table.setItem(row, col, item)

        table.scrollToBottom()

    def _update_counters(self):
        self._tx_status.setText(f"TX: {self._tx_count} | RX: {self._rx_count}")

    # ═══════════════════════════════════════════════════════════════════
    # Bereinigung
    # ═══════════════════════════════════════════════════════════════════

    def cleanup(self):
        """Muss von aussen aufgerufen werden (z.B. closeEvent)."""
        self._stop_periodic()
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
