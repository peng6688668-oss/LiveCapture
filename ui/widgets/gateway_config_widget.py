"""Gateway Konfigurations-Widget — Cross-Bus Routing-Regeln.

UI fuer das Hinzufuegen/Entfernen/Aktivieren von Routing-Regeln.
"""

import logging
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QLineEdit, QCheckBox,
    QHeaderView, QDialog, QFormLayout, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from core.gateway_engine import GatewayEngine, RoutingRule

_log = logging.getLogger(__name__)
_MONO = QFont("Consolas", 9)

_BUS_TYPES = ['CAN', 'LIN', 'Ethernet', 'FlexRay']
_TRANSFORMS = ['none', 'swap_bytes', 'truncate']


class AddRuleDialog(QDialog):
    """Dialog zum Hinzufuegen einer Routing-Regel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Routing-Regel hinzufuegen")
        self.setMinimumWidth(350)

        layout = QFormLayout(self)

        self._name_edit = QLineEdit("Regel 1")
        layout.addRow("Name:", self._name_edit)

        self._source_combo = QComboBox()
        self._source_combo.addItems(_BUS_TYPES)
        layout.addRow("Quelle:", self._source_combo)

        self._target_combo = QComboBox()
        self._target_combo.addItems(_BUS_TYPES)
        self._target_combo.setCurrentIndex(0)
        layout.addRow("Ziel:", self._target_combo)

        self._filter_edit = QLineEdit("-1")
        self._filter_edit.setFont(_MONO)
        self._filter_edit.setToolTip("-1 = alle IDs, sonst z.B. 0x123")
        layout.addRow("ID-Filter:", self._filter_edit)

        self._map_edit = QLineEdit("-1")
        self._map_edit.setFont(_MONO)
        self._map_edit.setToolTip("-1 = gleiche ID, sonst Ziel-ID")
        layout.addRow("ID-Mapping:", self._map_edit)

        self._transform_combo = QComboBox()
        self._transform_combo.addItems(_TRANSFORMS)
        layout.addRow("Transformation:", self._transform_combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_rule(self) -> RoutingRule:
        filter_text = self._filter_edit.text().strip()
        map_text = self._map_edit.text().strip()
        try:
            id_filter = int(filter_text, 16) if filter_text.startswith('0x') else int(filter_text)
        except ValueError:
            id_filter = -1
        try:
            id_map = int(map_text, 16) if map_text.startswith('0x') else int(map_text)
        except ValueError:
            id_map = -1

        return RoutingRule(
            name=self._name_edit.text().strip(),
            enabled=True,
            source_bus=self._source_combo.currentText(),
            target_bus=self._target_combo.currentText(),
            source_id_filter=id_filter,
            target_id_map=id_map,
            data_transform=self._transform_combo.currentText(),
        )


class GatewayConfigWidget(QWidget):
    """Gateway-Konfigurations-Panel mit Regel-Tabelle."""

    def __init__(self, engine: GatewayEngine, parent=None):
        super().__init__(parent)
        self._engine = engine
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header
        hdr = QHBoxLayout()
        hdr.setSpacing(4)
        title = QLabel("Gateway — Cross-Bus Routing")
        title.setStyleSheet("font-weight: bold; font-size: 11px;")
        hdr.addWidget(title)

        self._add_btn = QPushButton("+ Regel")
        self._add_btn.setMinimumWidth(80)
        self._add_btn.clicked.connect(self._on_add)
        hdr.addWidget(self._add_btn)

        self._remove_btn = QPushButton("- Entfernen")
        self._remove_btn.setMinimumWidth(90)
        self._remove_btn.clicked.connect(self._on_remove)
        hdr.addWidget(self._remove_btn)

        hdr.addStretch()

        self._status_label = QLabel("0 geroutet | 0 Fehler")
        self._status_label.setFont(_MONO)
        self._status_label.setStyleSheet("color: #888;")
        hdr.addWidget(self._status_label)
        layout.addLayout(hdr)

        # Tabelle
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            ['Aktiv', 'Name', 'Quelle', 'Ziel', 'ID-Filter',
             'ID-Map', 'Transform'])
        self._table.setFont(_MONO)
        self._table.setMaximumHeight(140)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h = self._table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for c in range(2, 7):
            h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._table)

        # Counter-Timer
        self._counter_timer = QTimer(self)
        self._counter_timer.setInterval(1000)
        self._counter_timer.timeout.connect(self._update_status)
        self._counter_timer.start()

        self._refresh_table()

    def _refresh_table(self):
        rules = self._engine.get_rules()
        self._table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            cb = QCheckBox()
            cb.setChecked(r.enabled)
            cb.stateChanged.connect(
                lambda state, idx=i: self._toggle_rule(idx, state == 2))
            self._table.setCellWidget(i, 0, cb)
            self._table.setItem(i, 1, QTableWidgetItem(r.name))
            self._table.setItem(i, 2, QTableWidgetItem(r.source_bus))
            self._table.setItem(i, 3, QTableWidgetItem(r.target_bus))
            filt = 'Alle' if r.source_id_filter < 0 else f'0x{r.source_id_filter:03X}'
            self._table.setItem(i, 4, QTableWidgetItem(filt))
            mp = 'Gleich' if r.target_id_map < 0 else f'0x{r.target_id_map:03X}'
            self._table.setItem(i, 5, QTableWidgetItem(mp))
            self._table.setItem(i, 6, QTableWidgetItem(r.data_transform))

    def _toggle_rule(self, idx: int, enabled: bool):
        rules = self._engine.get_rules()
        if 0 <= idx < len(rules):
            rules[idx].enabled = enabled

    def _on_add(self):
        dlg = AddRuleDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            rule = dlg.get_rule()
            self._engine.add_rule(rule)
            self._refresh_table()

    def _on_remove(self):
        idx = self._table.currentRow()
        if idx >= 0:
            self._engine.remove_rule(idx)
            self._refresh_table()

    def _update_status(self):
        self._status_label.setText(
            f"{self._engine.routed_count} geroutet"
            f" | {self._engine.error_count} Fehler")

    def cleanup(self):
        self._counter_timer.stop()