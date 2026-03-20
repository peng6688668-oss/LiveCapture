"""UDS Diagnose-Panel — Interaktive UDS-Requests ueber CAN (ISO-TP).

Funktionen:
  - Service-Auswahl (DiagnosticSessionControl, ReadDID, WriteDID, etc.)
  - DID-Schnellauswahl (F190=VIN, F18C=SerialNumber, etc.)
  - Request-Builder mit Hex-Editor
  - Response-Anzeige mit NRC-Dekodierung
  - ISO-TP Multi-Frame Unterstuetzung
"""

import logging
import time
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QLineEdit,
    QPushButton, QLabel, QTextEdit, QGroupBox, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from core.uds_codec import (
    UDS_SERVICES, UDS_SESSIONS, UDS_RESET_TYPES, COMMON_DIDS,
    build_request, build_tester_present, build_read_did,
    build_session_control, build_ecu_reset, build_clear_dtc,
    build_read_dtc, parse_response, get_service_name,
)
from core.uds_codec import ISOTPReassembler

_log = logging.getLogger(__name__)
_MONO = QFont("Consolas", 9)


class UDSDiagWidget(QWidget):
    """Interaktives UDS-Diagnose-Panel.

    Signale:
      send_can_frame(frame_id, data_bytes) — zum Senden ueber CAN-Bus
    """

    send_can_frame = pyqtSignal(int, bytes)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._reassembler = ISOTPReassembler()
        self._tx_id = 0x7DF   # Functional Request ID
        self._rx_id = 0x7E8   # Expected Response ID
        self._request_log: list = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # ── Adressierung ──
        addr_row = QHBoxLayout()
        addr_row.setSpacing(4)
        addr_row.addWidget(QLabel("TX-ID:"))
        self._tx_id_edit = QLineEdit("0x7DF")
        self._tx_id_edit.setFont(_MONO)
        self._tx_id_edit.setMaximumWidth(80)
        addr_row.addWidget(self._tx_id_edit)
        addr_row.addWidget(QLabel("RX-ID:"))
        self._rx_id_edit = QLineEdit("0x7E8")
        self._rx_id_edit.setFont(_MONO)
        self._rx_id_edit.setMaximumWidth(80)
        addr_row.addWidget(self._rx_id_edit)
        addr_row.addStretch()
        layout.addLayout(addr_row)

        # ── Service-Auswahl ──
        svc_row = QHBoxLayout()
        svc_row.setSpacing(4)
        svc_row.addWidget(QLabel("Service:"))
        self._service_combo = QComboBox()
        for sid, name in sorted(UDS_SERVICES.items()):
            self._service_combo.addItem(
                f"0x{sid:02X} {name}", sid)
        self._service_combo.currentIndexChanged.connect(self._on_service_changed)
        self._service_combo.setMinimumWidth(250)
        svc_row.addWidget(self._service_combo)
        svc_row.addStretch()
        layout.addLayout(svc_row)

        # ── Parameter-Zeile (kontextabhaengig) ──
        param_row = QHBoxLayout()
        param_row.setSpacing(4)

        self._param_label = QLabel("DID:")
        param_row.addWidget(self._param_label)

        self._did_combo = QComboBox()
        self._did_combo.setEditable(True)
        for did, name in sorted(COMMON_DIDS.items()):
            self._did_combo.addItem(f"0x{did:04X} {name}", did)
        self._did_combo.setMinimumWidth(300)
        param_row.addWidget(self._did_combo)

        self._sub_combo = QComboBox()
        self._sub_combo.hide()
        param_row.addWidget(self._sub_combo)

        param_row.addStretch()
        layout.addLayout(param_row)

        # ── Raw-Daten ──
        raw_row = QHBoxLayout()
        raw_row.setSpacing(4)
        raw_row.addWidget(QLabel("Daten:"))
        self._raw_edit = QLineEdit()
        self._raw_edit.setFont(_MONO)
        self._raw_edit.setPlaceholderText("Optional: zusaetzliche Hex-Daten")
        raw_row.addWidget(self._raw_edit, 1)

        self._send_btn = QPushButton("\u25b6 Senden")
        self._send_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;")
        self._send_btn.setMinimumWidth(100)
        self._send_btn.clicked.connect(self._on_send)
        raw_row.addWidget(self._send_btn)

        # Schnelltasten
        self._tester_present_btn = QPushButton("TesterPresent")
        self._tester_present_btn.setMinimumWidth(100)
        self._tester_present_btn.clicked.connect(self._send_tester_present)
        raw_row.addWidget(self._tester_present_btn)

        layout.addLayout(raw_row)

        # ── Ergebnis-Tabelle ──
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(5)
        self._result_table.setHorizontalHeaderLabels(
            ['Zeit', 'Richtung', 'Service', 'Ergebnis', 'Daten'])
        self._result_table.setFont(_MONO)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.verticalHeader().setDefaultSectionSize(20)
        self._result_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        h = self._result_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._result_table, 1)

        self._on_service_changed(0)

    def _on_service_changed(self, index: int):
        sid = self._service_combo.currentData()
        if sid in (0x22, 0x2E, 0x2F):  # ReadDID, WriteDID, IO Control
            self._param_label.setText("DID:")
            self._did_combo.show()
            self._sub_combo.hide()
        elif sid == 0x10:  # DiagnosticSessionControl
            self._param_label.setText("Session:")
            self._did_combo.hide()
            self._sub_combo.show()
            self._sub_combo.clear()
            for code, name in UDS_SESSIONS.items():
                self._sub_combo.addItem(f"0x{code:02X} {name}", code)
        elif sid == 0x11:  # ECUReset
            self._param_label.setText("Reset:")
            self._did_combo.hide()
            self._sub_combo.show()
            self._sub_combo.clear()
            for code, name in UDS_RESET_TYPES.items():
                self._sub_combo.addItem(f"0x{code:02X} {name}", code)
        else:
            self._param_label.setText("Sub:")
            self._did_combo.hide()
            self._sub_combo.show()
            self._sub_combo.clear()
            self._sub_combo.addItem("0x00", 0x00)

    def _on_send(self):
        """Baut UDS-Request und sendet via ISO-TP."""
        try:
            tx_id = int(self._tx_id_edit.text().strip(), 16)
        except ValueError:
            tx_id = 0x7DF
        self._tx_id = tx_id

        try:
            rx_id = int(self._rx_id_edit.text().strip(), 16)
        except ValueError:
            rx_id = 0x7E8
        self._rx_id = rx_id

        sid = self._service_combo.currentData()

        # Request bauen
        if sid in (0x22,):
            did_text = self._did_combo.currentText().strip()
            try:
                did = int(did_text.split()[0], 16)
            except (ValueError, IndexError):
                did = 0xF190
            uds_data = build_read_did(did)
        elif sid == 0x10:
            session = self._sub_combo.currentData() or 0x01
            uds_data = build_session_control(session)
        elif sid == 0x11:
            reset_type = self._sub_combo.currentData() or 0x01
            uds_data = build_ecu_reset(reset_type)
        elif sid == 0x3E:
            uds_data = build_tester_present()
        elif sid == 0x14:
            uds_data = build_clear_dtc()
        elif sid == 0x19:
            uds_data = build_read_dtc()
        else:
            sub = self._sub_combo.currentData() or 0x00
            extra = b''
            raw_text = self._raw_edit.text().strip()
            if raw_text:
                try:
                    extra = bytes.fromhex(raw_text.replace(' ', ''))
                except ValueError:
                    pass
            uds_data = build_request(sid, sub_function=sub, data=extra)

        # ISO-TP segmentieren und senden
        frames = self._reassembler.segment_request(uds_data)
        for frame in frames:
            self.send_can_frame.emit(tx_id, frame)

        # Log
        self._add_log('TX', get_service_name(sid),
                      '', uds_data.hex().upper())

    def _send_tester_present(self):
        try:
            tx_id = int(self._tx_id_edit.text().strip(), 16)
        except ValueError:
            tx_id = 0x7DF
        data = build_tester_present()
        frames = self._reassembler.segment_request(data)
        for f in frames:
            self.send_can_frame.emit(tx_id, f)
        self._add_log('TX', 'TesterPresent', '', data.hex().upper())

    def on_can_frame_received(self, can_id: int, data: bytes):
        """Wird aufgerufen wenn ein CAN-Frame empfangen wird (fuer ISO-TP)."""
        if can_id != self._rx_id:
            return
        result = self._reassembler.feed(can_id, data)
        if result is not None:
            resp = parse_response(result)
            status = "OK" if resp.is_positive else f"NRC: {resp.nrc_name}"
            self._add_log('RX', resp.service_name, status,
                          result.hex().upper())

    def _add_log(self, direction: str, service: str,
                 result: str, data: str):
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)
        ts = time.strftime('%H:%M:%S')
        items = [ts, direction, service, result, data]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if direction == 'TX':
                item.setForeground(Qt.GlobalColor.blue)
            elif 'NRC' in result:
                item.setForeground(Qt.GlobalColor.red)
            else:
                item.setForeground(Qt.GlobalColor.darkGreen)
            self._result_table.setItem(row, col, item)
        self._result_table.scrollToBottom()

    def cleanup(self):
        self._reassembler.clear()
