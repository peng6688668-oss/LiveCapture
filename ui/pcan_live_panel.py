"""PCAN-USB Pro FD Live-Panel mit TX/RX Vergleichsansicht.

Steuert PCAN-USB Pro FD ueber SocketCAN (python-can) und zeigt gesendete
und empfangene CAN-Nachrichten in einer geteilten Ansicht mit
Differenz-Hervorhebung.

Funktionen:
- Faltbares Konfigurationspanel (Schnittstelle, Bitrate, CAN-FD, Loopback)
- TX-Bereich: Sende-Konfiguration + Sende-Historie
- RX-Bereich: Empfangene Daten mit Differenz-Hervorhebung
- PLP-Bruecke: CCA/PLP → vcan Injection + Ratenanzeige
- Zyklisches Senden mit konfigurierbarem Intervall
"""

import logging
import socket
import struct
import subprocess
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QCheckBox, QHeaderView,
    QGroupBox, QMessageBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

from core.platform import get_can_interfaces, get_eth_interfaces

_log = logging.getLogger(__name__)

# ── python-can Import ───────────────────────────────────────────────────────
try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False

# ── superqt Import ──────────────────────────────────────────────────────────
try:
    from superqt import QCollapsible
    COLLAPSIBLE_AVAILABLE = True
except ImportError:
    COLLAPSIBLE_AVAILABLE = False

# ── Konstanten ──────────────────────────────────────────────────────────────
_HEADERS = ["Nr.", "Zeit", "Kanal", "CAN-ID", "Nachricht", "DLC", "Daten"]
_COL_NR = 0
_COL_ZEIT = 1
_COL_KANAL = 2
_COL_ID = 3
_COL_NAME = 4
_COL_DLC = 5
_COL_DATEN = 6

_TX_BG = QColor(220, 235, 255)       # Hellblau fuer TX-Zeilen
_RX_BG = QColor(255, 255, 255)       # Weiss fuer RX-Zeilen
_DIFF_FG = QColor(220, 50, 50)       # Rot fuer geaenderte Bytes
_CONNECTED_CLR = QColor(76, 175, 80)  # Gruen
_DISCONNECTED_CLR = QColor(244, 67, 54)  # Rot

_BITRATES = ["125000", "250000", "500000", "1000000"]
_FD_BITRATES = ["1000000", "2000000", "4000000", "5000000", "8000000"]

_MONO_FONT = QFont("Consolas", 9)
_MONO_FONT_BOLD = QFont("Consolas", 9, QFont.Weight.Bold)

_MAX_TABLE_ROWS = 10000

# PLP DataTypes fuer CAN
_PLP_CAN_TYPES = (0x0001, 0x0002, 0x0003)  # CAN Raw, CAN Data, CAN FD


# ═══════════════════════════════════════════════════════════════════════════
# CAN-Empfangsthread
# ═══════════════════════════════════════════════════════════════════════════

class CanReceiveThread(QThread):
    """Empfaengt CAN-Nachrichten in einem separaten Thread."""

    frame_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, bus, parent=None):
        super().__init__(parent)
        self._bus = bus
        self._running = True

    def run(self):
        """Empfangsschleife — blockiert mit Timeout fuer sauberes Beenden."""
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
        """Signalisiert dem Thread, sich zu beenden."""
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# PLP→CAN Bruecken-Thread
# ═══════════════════════════════════════════════════════════════════════════

class PlpCanBridgeThread(QThread):
    """Empfaengt PLP-Pakete (EtherType 0x2090) und extrahiert CAN-Frames.

    Optionale vcan-Injection: Extrahierte CAN-Frames werden in ein
    virtuelles CAN-Interface (vcan0) geschrieben, sodass andere Tools
    (candump, cansend, python-can) sie nutzen koennen.
    """

    frame_received = pyqtSignal(dict)
    rate_updated = pyqtSignal(int, int)  # plp_pps, can_fps
    error_occurred = pyqtSignal(str)

    def __init__(self, eth_iface: str, vcan_iface: str = 'vcan0',
                 inject_vcan: bool = True, parent=None):
        super().__init__(parent)
        self._eth_iface = eth_iface
        self._vcan_iface = vcan_iface
        self._inject_vcan = inject_vcan
        self._running = True

    def run(self):
        """Hauptschleife: PLP empfangen → CAN extrahieren → vcan injizieren."""
        # ── vcan Setup ──
        vcan_bus = None
        if self._inject_vcan and CAN_AVAILABLE:
            vcan_bus = self._setup_vcan()

        # ── AF_PACKET Socket oeffnen ──
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW,
                socket.htons(0x2090)
            )
            sock.bind((self._eth_iface, 0))
            sock.settimeout(0.5)
        except PermissionError:
            self.error_occurred.emit(
                f"Keine Berechtigung fuer AF_PACKET auf {self._eth_iface}.\n"
                "Starten mit: sudo oder CAP_NET_RAW setzen."
            )
            return
        except Exception as e:
            self.error_occurred.emit(f"Socket-Fehler: {e}")
            return

        _log.info("PLP-Bruecke gestartet: %s → %s",
                   self._eth_iface, self._vcan_iface)

        plp_count = 0
        can_count = 0
        last_rate_time = time.monotonic()

        while self._running:
            # ── Rate-Update pruefen ──
            now = time.monotonic()
            if now - last_rate_time >= 1.0:
                self.rate_updated.emit(plp_count, can_count)
                plp_count = 0
                can_count = 0
                last_rate_time = now

            # ── Paket empfangen ──
            try:
                raw = sock.recv(65536)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.error_occurred.emit(str(e))
                break

            # ── PLP Header pruefen ──
            if len(raw) < 26:
                continue
            data_type = int.from_bytes(raw[20:22], 'big')
            if data_type not in _PLP_CAN_TYPES:
                continue

            plp_count += 1
            is_fd = (data_type == 0x0003)

            # ── Entries durchlaufen und CAN-Frames extrahieren ──
            offset = 26  # 14 (Eth) + 12 (PLP Header)
            while offset + 16 <= len(raw):
                # Entry Header: CM_ID(2) + IfaceID(2) + Timestamp(8)
                #               + DataLength(2) + DataFlags(2)
                entry_ts_ns = int.from_bytes(raw[offset + 4:offset + 12], 'big')
                data_length = int.from_bytes(raw[offset + 12:offset + 14], 'big')

                payload_start = offset + 16
                payload_end = payload_start + data_length
                if payload_end > len(raw) or data_length == 0:
                    break

                # CAN-Payload: ID(4) + DLC(1) + Data(N)
                if data_length >= 5:
                    can_id_raw = int.from_bytes(
                        raw[payload_start:payload_start + 4], 'big')
                    extended = bool(can_id_raw & 0x80000000)
                    can_id = can_id_raw & 0x1FFFFFFF
                    dlc = raw[payload_start + 4]
                    can_data = bytes(
                        raw[payload_start + 5:payload_start + 5 + dlc])

                    ts_s = entry_ts_ns / 1e9

                    frame = {
                        'timestamp': ts_s,
                        'channel': self._eth_iface,
                        'can_id': can_id,
                        'is_extended': extended,
                        'dlc': dlc,
                        'data': can_data,
                        'is_fd': is_fd,
                    }

                    can_count += 1
                    self.frame_received.emit(frame)

                    # ── vcan Injection ──
                    if vcan_bus is not None:
                        try:
                            msg = can.Message(
                                arbitration_id=can_id,
                                data=can_data,
                                is_extended_id=extended,
                                is_fd=is_fd,
                            )
                            vcan_bus.send(msg)
                        except Exception:
                            pass

                offset = payload_end

        # ── Aufraeumen ──
        sock.close()
        if vcan_bus is not None:
            try:
                vcan_bus.shutdown()
            except Exception:
                pass
        _log.info("PLP-Bruecke gestoppt")

    def _setup_vcan(self) -> Optional[object]:
        """Erstellt vcan-Interface und oeffnet python-can Bus."""
        try:
            subprocess.run(
                ['sudo', 'ip', 'link', 'add', 'dev',
                 self._vcan_iface, 'type', 'vcan'],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', self._vcan_iface, 'up'],
                capture_output=True, timeout=5
            )
        except Exception as e:
            _log.warning("vcan Setup fehlgeschlagen: %s", e)
            return None

        try:
            bus = can.Bus(
                channel=self._vcan_iface,
                interface='socketcan',
            )
            _log.info("vcan Bus geoeffnet: %s", self._vcan_iface)
            return bus
        except Exception as e:
            _log.warning("vcan Bus oeffnen fehlgeschlagen: %s", e)
            return None

    def stop(self):
        """Signalisiert dem Thread, sich zu beenden."""
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# Haupt-Panel
# ═══════════════════════════════════════════════════════════════════════════

class PcanLivePanel(QWidget):
    """Live CAN Panel mit PCAN-USB Pro FD Steuerung.

    Kombiniert:
    - Faltbares PCAN-Konfigurationspanel (Schnittstelle, Bitrate, CAN-FD)
    - TX-Bereich: Sende-Konfiguration + Sende-Historie
    - RX-Bereich: Empfangene Daten mit PLP/CAN Ratenanzeige
    - PLP-Bruecke: CCA → vcan Injection
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bus: Optional[object] = None
        self._rx_thread: Optional[CanReceiveThread] = None
        self._bridge_thread: Optional[PlpCanBridgeThread] = None
        self._tx_count = 0
        self._rx_count = 0
        self._error_count = 0
        self._tx_reference: Dict[int, bytes] = {}  # CAN-ID → letzte TX-Daten
        self._start_time: Optional[float] = None
        self._periodic_timer: Optional[QTimer] = None
        self._periodic_count = 0
        self._init_ui()

    # ── UI-Aufbau ───────────────────────────────────────────────────────────

    def _init_ui(self):
        """Baut die gesamte Benutzeroberflaeche auf."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # --- Faltbares Konfigurationspanel ---
        layout.addWidget(self._create_config_panel())

        # --- TX/RX Splitter ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._create_tx_section())
        splitter.addWidget(self._create_rx_section())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        # --- Statusleiste ---
        self._status_label = QLabel(
            "Nicht verbunden | TX: 0 | RX: 0 | Fehler: 0"
        )
        self._status_label.setStyleSheet(
            "border-top: 1px solid #ccc; padding: 2px;"
        )
        layout.addWidget(self._status_label)

    # ── Konfigurationspanel ─────────────────────────────────────────────────

    def _create_config_panel(self) -> QWidget:
        """Erstellt das faltbare PCAN-Konfigurationspanel."""
        content = QWidget()
        clayout = QVBoxLayout(content)
        clayout.setContentsMargins(8, 4, 8, 4)
        clayout.setSpacing(4)

        # Zeile 1: Schnittstelle + Bitrate + CAN-FD
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        row1.addWidget(QLabel("Schnittstelle:"))
        self._iface_combo = QComboBox()
        self._iface_combo.setEditable(True)
        self._iface_combo.addItems(get_can_interfaces())
        self._iface_combo.setMinimumWidth(100)
        row1.addWidget(self._iface_combo)

        row1.addWidget(QLabel("Bitrate:"))
        self._bitrate_combo = QComboBox()
        self._bitrate_combo.setEditable(True)
        self._bitrate_combo.addItems(_BITRATES)
        self._bitrate_combo.setCurrentText("500000")
        self._bitrate_combo.setMinimumWidth(100)
        row1.addWidget(self._bitrate_combo)

        self._fd_check = QCheckBox("CAN-FD")
        self._fd_check.toggled.connect(self._on_fd_toggled)
        row1.addWidget(self._fd_check)

        row1.addWidget(QLabel("FD-Bitrate:"))
        self._fd_bitrate_combo = QComboBox()
        self._fd_bitrate_combo.setEditable(True)
        self._fd_bitrate_combo.addItems(_FD_BITRATES)
        self._fd_bitrate_combo.setCurrentText("2000000")
        self._fd_bitrate_combo.setEnabled(False)
        self._fd_bitrate_combo.setMinimumWidth(100)
        row1.addWidget(self._fd_bitrate_combo)

        self._loopback_check = QCheckBox("Loopback")
        self._loopback_check.setToolTip(
            "Aktiviert den Loopback-Modus\n"
            "(Empfang eigener Nachrichten ohne externe Geraete)"
        )
        row1.addWidget(self._loopback_check)

        row1.addStretch()
        clayout.addLayout(row1)

        # Zeile 2: Verbindung + Status
        row2 = QHBoxLayout()
        row2.setSpacing(6)

        self._connect_btn = QPushButton("Verbinden")
        self._connect_btn.setCheckable(True)
        self._connect_btn.toggled.connect(self._on_connect_toggled)
        self._connect_btn.setMinimumWidth(120)
        row2.addWidget(self._connect_btn)

        self._status_indicator = QLabel("\u25cf Getrennt")
        self._status_indicator.setStyleSheet(
            f"color: {_DISCONNECTED_CLR.name()}; font-weight: bold;"
        )
        row2.addWidget(self._status_indicator)

        self._device_info = QLabel("")
        self._device_info.setStyleSheet("color: #888;")
        row2.addWidget(self._device_info)

        row2.addStretch()
        clayout.addLayout(row2)

        # Zeile 3: PLP-Bruecke
        row3 = QHBoxLayout()
        row3.setSpacing(6)

        row3.addWidget(QLabel("PLP-Empfang:"))
        self._plp_iface_combo = QComboBox()
        self._plp_iface_combo.setEditable(True)
        self._plp_iface_combo.addItems(get_eth_interfaces())
        self._plp_iface_combo.setMinimumWidth(100)
        row3.addWidget(self._plp_iface_combo)

        self._vcan_check = QCheckBox("vcan Injection")
        self._vcan_check.setChecked(True)
        self._vcan_check.setToolTip(
            "CAN-Frames in vcan0 injizieren\n"
            "(fuer candump, cansend, python-can)"
        )
        row3.addWidget(self._vcan_check)

        self._bridge_start_btn = QPushButton("Bruecke starten")
        self._bridge_start_btn.clicked.connect(self._start_bridge)
        row3.addWidget(self._bridge_start_btn)

        self._bridge_stop_btn = QPushButton("Stopp")
        self._bridge_stop_btn.clicked.connect(self._stop_bridge)
        self._bridge_stop_btn.setEnabled(False)
        row3.addWidget(self._bridge_stop_btn)

        self._bridge_status = QLabel("")
        self._bridge_status.setStyleSheet("color: #888;")
        row3.addWidget(self._bridge_status)

        row3.addStretch()
        clayout.addLayout(row3)

        # In QCollapsible oder QGroupBox verpacken
        if COLLAPSIBLE_AVAILABLE:
            collapsible = QCollapsible("PCAN-USB Pro FD Konfiguration")
            collapsible.addWidget(content)
            collapsible.expand()
            return collapsible

        group = QGroupBox("PCAN-USB Pro FD Konfiguration")
        group.setCheckable(True)
        group.setChecked(True)
        gl = QVBoxLayout(group)
        gl.addWidget(content)
        return group

    # ── TX-Bereich ──────────────────────────────────────────────────────────

    def _create_tx_section(self) -> QWidget:
        """Erstellt den TX-Bereich (Sende-Konfiguration + Historie)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # TX-Header
        header = QLabel("TX \u2014 Sende-Konfiguration")
        header.setStyleSheet(
            "font-weight: bold; background-color: #1565C0;"
            "color: white; padding: 4px;"
        )
        layout.addWidget(header)

        # Sende-Zeile
        send_row = QHBoxLayout()
        send_row.setSpacing(4)

        send_row.addWidget(QLabel("CAN-ID:"))
        self._tx_id = QLineEdit("0x123")
        self._tx_id.setMaximumWidth(100)
        self._tx_id.setFont(_MONO_FONT)
        send_row.addWidget(self._tx_id)

        self._tx_extended = QCheckBox("Ext")
        self._tx_extended.setToolTip("Extended ID (29-Bit)")
        send_row.addWidget(self._tx_extended)

        send_row.addWidget(QLabel("DLC:"))
        self._tx_dlc = QSpinBox()
        self._tx_dlc.setRange(0, 8)
        self._tx_dlc.setValue(8)
        self._tx_dlc.setMaximumWidth(60)
        send_row.addWidget(self._tx_dlc)

        send_row.addWidget(QLabel("Daten:"))
        self._tx_data_edit = QLineEdit("00 11 22 33 44 55 66 77")
        self._tx_data_edit.setFont(_MONO_FONT)
        self._tx_data_edit.setPlaceholderText("00 11 22 33 ...")
        send_row.addWidget(self._tx_data_edit, 1)

        self._send_btn = QPushButton("\u25b6 Senden")
        self._send_btn.clicked.connect(self._send_frame)
        self._send_btn.setEnabled(False)
        self._send_btn.setMinimumWidth(100)
        send_row.addWidget(self._send_btn)

        layout.addLayout(send_row)

        # Periodisches Senden
        periodic_row = QHBoxLayout()
        periodic_row.setSpacing(4)

        periodic_row.addWidget(QLabel("Zyklisch:"))
        periodic_row.addWidget(QLabel("Intervall:"))
        self._periodic_interval = QSpinBox()
        self._periodic_interval.setRange(1, 60000)
        self._periodic_interval.setValue(100)
        self._periodic_interval.setSuffix(" ms")
        self._periodic_interval.setMaximumWidth(120)
        periodic_row.addWidget(self._periodic_interval)

        self._periodic_start_btn = QPushButton("Start")
        self._periodic_start_btn.clicked.connect(self._start_periodic)
        self._periodic_start_btn.setEnabled(False)
        periodic_row.addWidget(self._periodic_start_btn)

        self._periodic_stop_btn = QPushButton("Stopp")
        self._periodic_stop_btn.clicked.connect(self._stop_periodic)
        self._periodic_stop_btn.setEnabled(False)
        periodic_row.addWidget(self._periodic_stop_btn)

        self._periodic_label = QLabel("")
        periodic_row.addWidget(self._periodic_label)

        periodic_row.addStretch()
        layout.addLayout(periodic_row)

        # TX-Tabelle
        self._tx_table = QTableWidget()
        self._tx_table.setColumnCount(7)
        self._tx_table.setHorizontalHeaderLabels(_HEADERS)
        self._setup_table(self._tx_table)
        layout.addWidget(self._tx_table)

        return widget

    # ── RX-Bereich ──────────────────────────────────────────────────────────

    def _create_rx_section(self) -> QWidget:
        """Erstellt den RX-Bereich (Empfangene Daten + PLP/CAN Rate)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # RX-Header mit Ratenanzeige
        rx_header = QHBoxLayout()
        rx_header.setSpacing(0)

        header = QLabel("RX \u2014 Empfangene Daten")
        header.setStyleSheet(
            "font-weight: bold; background-color: #2E7D32;"
            "color: white; padding: 4px;"
        )
        rx_header.addWidget(header)

        # PLP Rate Label
        self._plp_rate_label = QLabel("  PLP: \u2014 Pkt/s")
        self._plp_rate_label.setFont(QFont("Consolas", 9))
        self._plp_rate_label.setStyleSheet(
            "background-color: #2E7D32; color: #FFD54F;"
            "padding: 4px; font-weight: bold;"
        )
        rx_header.addWidget(self._plp_rate_label)

        # CAN Rate Label
        self._can_rate_label = QLabel("  CAN: \u2014 Frames/s")
        self._can_rate_label.setFont(QFont("Consolas", 9))
        self._can_rate_label.setStyleSheet(
            "background-color: #2E7D32; color: #B9F6CA;"
            "padding: 4px; font-weight: bold;"
        )
        rx_header.addWidget(self._can_rate_label)

        # Spacer
        spacer = QLabel("")
        spacer.setStyleSheet("background-color: #2E7D32;")
        rx_header.addWidget(spacer, 1)

        self._rx_clear_btn = QPushButton("Loeschen")
        self._rx_clear_btn.clicked.connect(self._clear_rx)
        rx_header.addWidget(self._rx_clear_btn)

        self._rx_pause_btn = QPushButton("Pause")
        self._rx_pause_btn.setCheckable(True)
        rx_header.addWidget(self._rx_pause_btn)

        layout.addLayout(rx_header)

        # RX-Tabelle
        self._rx_table = QTableWidget()
        self._rx_table.setColumnCount(7)
        self._rx_table.setHorizontalHeaderLabels(_HEADERS)
        self._setup_table(self._rx_table)
        layout.addWidget(self._rx_table)

        return widget

    # ── Tabellen-Setup ──────────────────────────────────────────────────────

    @staticmethod
    def _setup_table(table: QTableWidget):
        """Konfiguriert eine Trace-Tabelle (CANoe-Style)."""
        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)

        h = table.horizontalHeader()
        h.setSectionResizeMode(_COL_NR, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(_COL_ZEIT, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(_COL_KANAL, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(_COL_ID, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(_COL_NAME, QHeaderView.ResizeMode.Interactive)
        h.setSectionResizeMode(_COL_DLC, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(_COL_DATEN, QHeaderView.ResizeMode.Interactive)

        # Daten und Nachricht: gleiche Standardbreite fuer TX und RX
        table.setColumnWidth(_COL_NAME, 200)
        table.setColumnWidth(_COL_DATEN, 300)

        # Letzte Spalte dehnt sich, damit kein Leerraum rechts entsteht
        h.setStretchLastSection(True)

        # Doppelklick auf Header → Spalte automatisch an Inhalt anpassen
        h.sectionDoubleClicked.connect(
            lambda col: table.resizeColumnToContents(col)
        )

        # Einheitlicher Header-Stil (kein schwarzer Hintergrund)
        h.setStyleSheet(
            "QHeaderView::section {"
            "  background-color: transparent;"
            "  border: 1px solid #c0c0c0;"
            "  padding: 4px;"
            "  font-weight: bold;"
            "  font-size: 9pt;"
            "}"
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Verbindung
    # ═══════════════════════════════════════════════════════════════════════

    def _on_fd_toggled(self, checked: bool):
        """CAN-FD Checkbox geaendert."""
        self._fd_bitrate_combo.setEnabled(checked)
        self._tx_dlc.setRange(0, 64 if checked else 8)

    def _on_connect_toggled(self, checked: bool):
        """Verbinden/Trennen Toggle."""
        if checked:
            self._connect_device()
        else:
            self._disconnect_device()

    def _configure_interface(self, interface: str, bitrate: int,
                             fd: bool = False, fd_bitrate: int = 2000000,
                             loopback: bool = False) -> bool:
        """Konfiguriert die CAN-Schnittstelle ueber ip link."""
        try:
            # Interface herunterfahren (Fehler ignorieren falls schon unten)
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                capture_output=True, timeout=5
            )

            # Bitrate und Modus setzen
            cmd = [
                'sudo', 'ip', 'link', 'set', interface,
                'type', 'can', 'bitrate', str(bitrate),
            ]
            if fd:
                cmd.extend(['dbitrate', str(fd_bitrate), 'fd', 'on'])
            if loopback:
                cmd.extend(['loopback', 'on'])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                _log.error(
                    "Interface konfigurieren fehlgeschlagen: %s",
                    result.stderr.strip()
                )
                return False

            # Interface hochfahren
            result = subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'up'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                _log.error(
                    "Interface hochfahren fehlgeschlagen: %s",
                    result.stderr.strip()
                )
                return False

            return True

        except subprocess.TimeoutExpired:
            _log.error("Timeout bei Interface-Konfiguration")
            return False
        except FileNotFoundError:
            _log.error("'ip' Befehl nicht gefunden")
            return False

    def _connect_device(self):
        """Verbindet mit dem PCAN-USB Pro FD ueber SocketCAN."""
        if not CAN_AVAILABLE:
            QMessageBox.warning(
                self, "Fehler",
                "python-can ist nicht installiert.\n"
                "Installation: pip install python-can"
            )
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
                fd_bitrate = 2000000
        loopback = self._loopback_check.isChecked()

        # Schnittstelle konfigurieren (ip link set)
        if not self._configure_interface(
            interface, bitrate, fd, fd_bitrate, loopback
        ):
            QMessageBox.warning(
                self, "Verbindungsfehler",
                f"Schnittstelle '{interface}' konnte nicht konfiguriert "
                f"werden.\n\n"
                "Moegliche Ursachen:\n"
                "\u2022 PCAN-USB Pro FD nicht angeschlossen\n"
                "\u2022 peak_usb Treiber nicht geladen "
                "(sudo modprobe peak_usb)\n"
                "\u2022 Keine sudo-Berechtigung\n\n"
                "Pruefen: lsusb | grep PEAK"
            )
            self._connect_btn.setChecked(False)
            return

        # python-can Bus oeffnen
        try:
            self._bus = can.Bus(
                channel=interface,
                interface='socketcan',
                fd=fd,
                receive_own_messages=loopback,
            )
        except can.CanError as e:
            QMessageBox.warning(
                self, "Verbindungsfehler",
                f"python-can Bus konnte nicht geoeffnet werden:\n{e}"
            )
            self._connect_btn.setChecked(False)
            return

        # Empfangsthread starten
        self._rx_thread = CanReceiveThread(self._bus, self)
        self._rx_thread.frame_received.connect(self._on_frame_received)
        self._rx_thread.error_occurred.connect(self._on_rx_error)
        self._rx_thread.start()

        self._start_time = time.time()

        # UI aktualisieren
        self._status_indicator.setText("\u25cf Verbunden")
        self._status_indicator.setStyleSheet(
            f"color: {_CONNECTED_CLR.name()}; font-weight: bold;"
        )
        fd_info = f" FD @{fd_bitrate}" if fd else ""
        self._device_info.setText(
            f"{interface} @ {bitrate} Bit/s{fd_info}"
        )
        self._connect_btn.setText("Trennen")
        self._send_btn.setEnabled(True)
        self._periodic_start_btn.setEnabled(True)

        # Konfiguration sperren
        for w in (self._iface_combo, self._bitrate_combo,
                  self._fd_check, self._fd_bitrate_combo,
                  self._loopback_check):
            w.setEnabled(False)

        _log.info("PCAN verbunden: %s @ %d", interface, bitrate)

    def _disconnect_device(self):
        """Trennt die Verbindung zum PCAN-USB Pro FD."""
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

        # Interface herunterfahren
        interface = self._iface_combo.currentText().strip()
        try:
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        # UI aktualisieren
        self._status_indicator.setText("\u25cf Getrennt")
        self._status_indicator.setStyleSheet(
            f"color: {_DISCONNECTED_CLR.name()}; font-weight: bold;"
        )
        self._device_info.setText("")
        self._connect_btn.setText("Verbinden")
        self._send_btn.setEnabled(False)
        self._periodic_start_btn.setEnabled(False)
        self._periodic_stop_btn.setEnabled(False)

        # Konfiguration entsperren
        for w in (self._iface_combo, self._bitrate_combo,
                  self._fd_check, self._loopback_check):
            w.setEnabled(True)
        self._fd_bitrate_combo.setEnabled(self._fd_check.isChecked())

        _log.info("PCAN getrennt")

    # ═══════════════════════════════════════════════════════════════════════
    # PLP-Bruecke
    # ═══════════════════════════════════════════════════════════════════════

    def _start_bridge(self):
        """Startet die PLP→CAN Bruecke."""
        if self._bridge_thread is not None:
            return

        eth_iface = self._plp_iface_combo.currentText().strip()
        if not eth_iface:
            QMessageBox.warning(self, "Fehler", "Kein Netzwerk-Interface gewaehlt")
            return

        inject_vcan = self._vcan_check.isChecked()

        self._bridge_thread = PlpCanBridgeThread(
            eth_iface=eth_iface,
            vcan_iface='vcan0',
            inject_vcan=inject_vcan,
            parent=self,
        )
        self._bridge_thread.frame_received.connect(self._on_frame_received)
        self._bridge_thread.rate_updated.connect(self._on_bridge_rate)
        self._bridge_thread.error_occurred.connect(self._on_bridge_error)
        self._bridge_thread.start()

        self._bridge_start_btn.setEnabled(False)
        self._bridge_stop_btn.setEnabled(True)
        self._plp_iface_combo.setEnabled(False)
        self._vcan_check.setEnabled(False)

        vcan_info = " → vcan0" if inject_vcan else ""
        self._bridge_status.setText(
            f"\u25cf {eth_iface}{vcan_info}"
        )
        self._bridge_status.setStyleSheet(
            f"color: {_CONNECTED_CLR.name()}; font-weight: bold;"
        )

    def _stop_bridge(self):
        """Stoppt die PLP→CAN Bruecke."""
        if self._bridge_thread is not None:
            self._bridge_thread.stop()
            self._bridge_thread.wait(3000)
            self._bridge_thread = None

        self._bridge_start_btn.setEnabled(True)
        self._bridge_stop_btn.setEnabled(False)
        self._plp_iface_combo.setEnabled(True)
        self._vcan_check.setEnabled(True)
        self._bridge_status.setText("")

        self._plp_rate_label.setText("  PLP: \u2014 Pkt/s")
        self._can_rate_label.setText("  CAN: \u2014 Frames/s")

    def _on_bridge_rate(self, plp_pps: int, can_fps: int):
        """Aktualisiert die PLP/CAN Ratenanzeige im RX-Header."""
        self._plp_rate_label.setText(f"  PLP: {plp_pps} Pkt/s")
        self._can_rate_label.setText(f"  CAN: {can_fps} Frames/s")

    def _on_bridge_error(self, error: str):
        """Behandelt Fehler der PLP-Bruecke."""
        _log.error("PLP-Bruecke Fehler: %s", error)
        self._bridge_status.setText(f"Fehler: {error[:60]}")
        self._bridge_status.setStyleSheet(
            f"color: {_DISCONNECTED_CLR.name()};"
        )
        self._stop_bridge()
        QMessageBox.warning(self, "PLP-Bruecke Fehler", error)

    # ═══════════════════════════════════════════════════════════════════════
    # Senden
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_can_id(self) -> Optional[int]:
        """Parst die CAN-ID aus dem Eingabefeld."""
        text = self._tx_id.text().strip()
        try:
            if text.lower().startswith('0x'):
                return int(text, 16)
            return int(text)
        except ValueError:
            return None

    def _parse_hex_data(self) -> Optional[bytes]:
        """Parst die Hex-Daten aus dem Eingabefeld."""
        text = self._tx_data_edit.text().strip()
        if not text:
            return b''
        hex_str = text.replace(' ', '')
        if len(hex_str) % 2 != 0:
            hex_str = hex_str[:-1]
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return None

    def _send_frame(self):
        """Sendet einen CAN-Frame ueber PCAN-USB Pro FD."""
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

        extended = self._tx_extended.isChecked()
        fd = self._fd_check.isChecked()

        msg = can.Message(
            arbitration_id=can_id,
            data=data,
            is_extended_id=extended,
            is_fd=fd,
        )

        try:
            self._bus.send(msg)
            self._tx_count += 1

            # TX-Referenz fuer Differenz-Hervorhebung
            self._tx_reference[can_id] = bytes(data)

            # TX-Tabelle aktualisieren
            elapsed = time.time() - (self._start_time or time.time())
            self._add_row(self._tx_table, self._tx_count, {
                'timestamp': elapsed,
                'channel': self._iface_combo.currentText(),
                'can_id': can_id,
                'is_extended': extended,
                'dlc': len(data),
                'data': data,
                'is_fd': fd,
            }, is_tx=True)

            self._update_status()

        except Exception as e:
            self._error_count += 1
            _log.error("CAN-Senden fehlgeschlagen: %s", e)
            self._update_status()

    def _start_periodic(self):
        """Startet zyklisches Senden."""
        if self._bus is None:
            return
        self._stop_periodic()

        interval = self._periodic_interval.value()
        self._periodic_count = 0

        self._periodic_timer = QTimer(self)
        self._periodic_timer.timeout.connect(self._on_periodic_tick)
        self._periodic_timer.start(interval)

        self._periodic_start_btn.setEnabled(False)
        self._periodic_stop_btn.setEnabled(True)
        self._periodic_label.setText("Zyklisch aktiv: 0 gesendet")

    def _stop_periodic(self):
        """Stoppt zyklisches Senden."""
        if self._periodic_timer is not None:
            self._periodic_timer.stop()
            self._periodic_timer.deleteLater()
            self._periodic_timer = None

        self._periodic_start_btn.setEnabled(self._bus is not None)
        self._periodic_stop_btn.setEnabled(False)
        if self._periodic_count > 0:
            self._periodic_label.setText(
                f"Gestoppt: {self._periodic_count} gesendet"
            )

    def _on_periodic_tick(self):
        """Timer-Callback fuer zyklisches Senden."""
        self._send_frame()
        self._periodic_count += 1
        self._periodic_label.setText(
            f"Zyklisch aktiv: {self._periodic_count} gesendet"
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Empfang
    # ═══════════════════════════════════════════════════════════════════════

    def _on_frame_received(self, frame: dict):
        """Callback wenn ein CAN-Frame empfangen wird (aus RX-Thread oder PLP-Bruecke)."""
        if self._rx_pause_btn.isChecked():
            return

        self._rx_count += 1

        # Relative Zeitberechnung
        if self._start_time is not None and frame['timestamp'] > 1e9:
            frame = {**frame, 'timestamp': frame['timestamp'] - self._start_time}

        self._add_row(self._rx_table, self._rx_count, frame, is_tx=False)
        self._update_status()

    def _on_rx_error(self, error: str):
        """Callback bei Empfangsfehler."""
        self._error_count += 1
        _log.error("CAN-Empfang Fehler: %s", error)
        self._update_status()

    # ═══════════════════════════════════════════════════════════════════════
    # Tabellen-Verwaltung
    # ═══════════════════════════════════════════════════════════════════════

    def _add_row(self, table: QTableWidget, nr: int,
                 frame: dict, is_tx: bool):
        """Fuegt eine Zeile zur TX- oder RX-Tabelle hinzu."""
        row = table.rowCount()
        table.insertRow(row)

        # Ringpuffer: aelteste Zeile entfernen
        if row >= _MAX_TABLE_ROWS:
            table.removeRow(0)
            row -= 1

        can_id = frame['can_id']
        data = frame.get('data', b'')
        is_ext = frame.get('is_extended', False)
        id_fmt = f"0x{can_id:08X}" if is_ext else f"0x{can_id:03X}"
        data_hex = ' '.join(f'{b:02X}' for b in data)

        bg = _TX_BG if is_tx else _RX_BG
        cells = [
            (str(nr), Qt.AlignmentFlag.AlignRight),
            (f"{frame['timestamp']:.6f}", Qt.AlignmentFlag.AlignRight),
            (frame.get('channel', ''), Qt.AlignmentFlag.AlignCenter),
            (id_fmt, Qt.AlignmentFlag.AlignRight),
            ("-", Qt.AlignmentFlag.AlignLeft),
            (str(frame.get('dlc', len(data))), Qt.AlignmentFlag.AlignRight),
            (data_hex, Qt.AlignmentFlag.AlignLeft),
        ]

        for col, (text, align) in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
            item.setBackground(bg)
            if col in (_COL_ZEIT, _COL_ID, _COL_DATEN):
                item.setFont(_MONO_FONT)
            table.setItem(row, col, item)

        # Differenz-Hervorhebung (nur RX)
        if not is_tx and can_id in self._tx_reference:
            self._highlight_diff(table, row, data, self._tx_reference[can_id])

        table.scrollToBottom()

    def _highlight_diff(self, table: QTableWidget, row: int,
                        rx_data: bytes, tx_data: bytes):
        """Hebt geaenderte Bytes rot hervor (RX vs TX Vergleich)."""
        if rx_data == tx_data:
            return

        # Byte-weisen Vergleich erstellen
        max_len = max(len(rx_data), len(tx_data))
        has_diff = False

        for i in range(max_len):
            rx_b = rx_data[i] if i < len(rx_data) else None
            tx_b = tx_data[i] if i < len(tx_data) else None
            if rx_b != tx_b:
                has_diff = True
                break

        if has_diff:
            item = table.item(row, _COL_DATEN)
            if item is not None:
                item.setForeground(_DIFF_FG)
                item.setFont(_MONO_FONT_BOLD)
                tx_hex = ' '.join(f'{b:02X}' for b in tx_data)
                rx_hex = ' '.join(f'{b:02X}' for b in rx_data)
                item.setToolTip(f"TX: {tx_hex}\nRX: {rx_hex}")

    def _clear_rx(self):
        """Loescht die RX-Tabelle."""
        self._rx_table.setRowCount(0)
        self._rx_count = 0
        self._update_status()

    def _update_status(self):
        """Aktualisiert die Statusleiste."""
        state = "Verbunden" if self._bus else "Getrennt"
        bridge = " | Bruecke aktiv" if self._bridge_thread else ""
        self._status_label.setText(
            f"{state} | TX: {self._tx_count} | "
            f"RX: {self._rx_count} | Fehler: {self._error_count}{bridge}"
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Bereinigung
    # ═══════════════════════════════════════════════════════════════════════

    def closeEvent(self, event):
        """Bereinigt Threads und Sockets beim Schliessen."""
        self._stop_periodic()
        self._stop_bridge()
        if self._rx_thread is not None:
            self._rx_thread.stop()
            self._rx_thread.wait(2000)
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
        super().closeEvent(event)
