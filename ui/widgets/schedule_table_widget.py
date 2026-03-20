"""Schedule Table — Multi-Frame zyklisches Senden fuer CAN/LIN.

Zeigt eine editierbare Tabelle: [Aktiv] [ID] [DLC] [Daten] [Zyklus(ms)] [Name]
Ein einzelner Dispatcher-Timer feuert im GCD-Intervall aller Zykluszeiten.
"""

from dataclasses import dataclass
from math import gcd
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QCheckBox, QHeaderView, QMessageBox,
    QLineEdit, QSpinBox, QDialog, QFormLayout, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

_MONO = QFont("Consolas", 9)


@dataclass
class ScheduleRow:
    """Eine Zeile in der Schedule-Tabelle."""
    enabled: bool = True
    frame_id: int = 0
    dlc: int = 8
    data: bytes = b'\x00' * 8
    cycle_ms: int = 100
    name: str = ''


class AddRowDialog(QDialog):
    """Dialog zum Hinzufuegen einer neuen Schedule-Zeile."""

    def __init__(self, bus_type: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Eintrag hinzufuegen")
        self.setMinimumWidth(300)
        self._bus_type = bus_type

        layout = QFormLayout(self)

        self._id_edit = QLineEdit("0x123" if bus_type == 'CAN' else "0x00")
        self._id_edit.setFont(_MONO)
        layout.addRow("ID:", self._id_edit)

        self._dlc_spin = QSpinBox()
        self._dlc_spin.setRange(0, 64 if bus_type == 'CAN' else 8)
        self._dlc_spin.setValue(8)
        layout.addRow("DLC:", self._dlc_spin)

        self._data_edit = QLineEdit("00 00 00 00 00 00 00 00")
        self._data_edit.setFont(_MONO)
        layout.addRow("Daten:", self._data_edit)

        self._cycle_spin = QSpinBox()
        self._cycle_spin.setRange(1, 60000)
        self._cycle_spin.setValue(100)
        self._cycle_spin.setSuffix(" ms")
        layout.addRow("Zyklus:", self._cycle_spin)

        self._name_edit = QLineEdit()
        layout.addRow("Name:", self._name_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_row(self) -> Optional[ScheduleRow]:
        id_text = self._id_edit.text().strip()
        try:
            frame_id = int(id_text, 16) if id_text.startswith('0x') else int(id_text)
        except ValueError:
            return None
        data_text = self._data_edit.text().strip()
        try:
            data = bytes.fromhex(data_text.replace(' ', ''))
        except ValueError:
            data = b''
        return ScheduleRow(
            enabled=True,
            frame_id=frame_id,
            dlc=self._dlc_spin.value(),
            data=data,
            cycle_ms=self._cycle_spin.value(),
            name=self._name_edit.text().strip(),
        )


class ScheduleTableWidget(QWidget):
    """Wiederverwendbare Schedule-Tabelle fuer CAN/LIN."""

    frame_to_send = pyqtSignal(dict)

    def __init__(self, bus_type: str = 'CAN', parent=None):
        super().__init__(parent)
        self._bus_type = bus_type
        self._rows: List[ScheduleRow] = []
        self._gcd_interval = 1
        self._dispatcher: Optional[QTimer] = None
        self._elapsed_ms = 0
        self._next_fires: Dict[int, int] = {}
        self._send_counts: Dict[int, int] = {}
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Toolbar
        tb = QHBoxLayout()
        tb.setSpacing(4)

        self._add_btn = QPushButton("+ Hinzufuegen")
        self._add_btn.setMinimumWidth(100)
        self._add_btn.clicked.connect(self._on_add)
        tb.addWidget(self._add_btn)

        self._remove_btn = QPushButton("- Entfernen")
        self._remove_btn.setMinimumWidth(100)
        self._remove_btn.clicked.connect(self._on_remove)
        tb.addWidget(self._remove_btn)

        self._start_btn = QPushButton("\u25b6 Start")
        self._start_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;")
        self._start_btn.setMinimumWidth(80)
        self._start_btn.clicked.connect(self.start)
        tb.addWidget(self._start_btn)

        self._stop_btn = QPushButton("\u2b1b Stop")
        self._stop_btn.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;")
        self._stop_btn.setMinimumWidth(80)
        self._stop_btn.clicked.connect(self.stop)
        self._stop_btn.setEnabled(False)
        tb.addWidget(self._stop_btn)

        tb.addStretch()
        self._status = QLabel("Gestoppt")
        self._status.setFont(_MONO)
        self._status.setStyleSheet("color: #888;")
        tb.addWidget(self._status)
        layout.addLayout(tb)

        # Tabelle
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            ['Aktiv', 'ID', 'DLC', 'Daten', 'Zyklus (ms)', 'Name'])
        self._table.setFont(_MONO)
        self._table.setMaximumHeight(160)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h = self._table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

    def _refresh_table(self):
        self._table.setRowCount(len(self._rows))
        for i, r in enumerate(self._rows):
            cb = QCheckBox()
            cb.setChecked(r.enabled)
            cb.stateChanged.connect(
                lambda state, idx=i: self._toggle_row(idx, state == 2))
            self._table.setCellWidget(i, 0, cb)

            id_fmt = f"0x{r.frame_id:03X}" if self._bus_type == 'CAN' else f"0x{r.frame_id:02X}"
            self._table.setItem(i, 1, QTableWidgetItem(id_fmt))
            self._table.setItem(i, 2, QTableWidgetItem(str(r.dlc)))
            hex_str = ' '.join(f'{b:02X}' for b in r.data[:r.dlc])
            self._table.setItem(i, 3, QTableWidgetItem(hex_str))
            self._table.setItem(i, 4, QTableWidgetItem(str(r.cycle_ms)))
            self._table.setItem(i, 5, QTableWidgetItem(r.name))

            cnt = self._send_counts.get(i, 0)
            if cnt > 0:
                item = self._table.item(i, 5)
                if item:
                    item.setText(f"{r.name}  [{cnt}]")

    def _toggle_row(self, idx: int, enabled: bool):
        if 0 <= idx < len(self._rows):
            self._rows[idx].enabled = enabled

    def _recalc_gcd(self):
        cycles = [r.cycle_ms for r in self._rows if r.enabled and r.cycle_ms > 0]
        if not cycles:
            self._gcd_interval = 1
            return
        result = cycles[0]
        for c in cycles[1:]:
            result = gcd(result, c)
        self._gcd_interval = max(1, result)

    # ── Oeffentliche API ──

    def add_row(self, row: ScheduleRow):
        self._rows.append(row)
        self._refresh_table()

    def _on_add(self):
        dlg = AddRowDialog(self._bus_type, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            row = dlg.get_row()
            if row:
                self.add_row(row)

    def _on_remove(self):
        idx = self._table.currentRow()
        if 0 <= idx < len(self._rows):
            self._rows.pop(idx)
            self._refresh_table()

    def start(self):
        if not self._rows:
            return
        self._recalc_gcd()
        self._elapsed_ms = 0
        self._next_fires = {}
        self._send_counts = {}
        for i, r in enumerate(self._rows):
            if r.enabled:
                self._next_fires[i] = 0
                self._send_counts[i] = 0
        self._dispatcher = QTimer(self)
        self._dispatcher.timeout.connect(self._tick)
        self._dispatcher.start(self._gcd_interval)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._add_btn.setEnabled(False)
        self._remove_btn.setEnabled(False)
        self._status.setText("Aktiv")
        self._status.setStyleSheet("color: #4CAF50; font-weight: bold;")

    def stop(self):
        if self._dispatcher:
            self._dispatcher.stop()
            self._dispatcher.deleteLater()
            self._dispatcher = None
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._add_btn.setEnabled(True)
        self._remove_btn.setEnabled(True)
        total = sum(self._send_counts.values())
        self._status.setText(f"Gestoppt ({total} gesendet)")
        self._status.setStyleSheet("color: #888;")

    def _tick(self):
        for i, r in enumerate(self._rows):
            if not r.enabled or i not in self._next_fires:
                continue
            if self._elapsed_ms >= self._next_fires[i]:
                self.frame_to_send.emit({
                    'frame_id': r.frame_id,
                    'dlc': r.dlc,
                    'data': bytes(r.data[:r.dlc]),
                    'bus_type': self._bus_type,
                    'name': r.name,
                })
                self._send_counts[i] = self._send_counts.get(i, 0) + 1
                self._next_fires[i] += r.cycle_ms
        self._elapsed_ms += self._gcd_interval
        # Tabelle alle 500ms aktualisieren (Performance)
        if self._elapsed_ms % 500 < self._gcd_interval:
            self._refresh_table()

    def is_running(self) -> bool:
        return self._dispatcher is not None and self._dispatcher.isActive()

    def get_rows(self) -> List[ScheduleRow]:
        return list(self._rows)

    def cleanup(self):
        self.stop()
