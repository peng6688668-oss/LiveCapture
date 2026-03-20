"""Automotive Ethernet Live-Seite fuer RX-Monitoring.

Ethernet-Daten kommen ueber TECMP/PLP (DataType 0x0080/0x0081).
Unterstuetzte physikalische Schichten:
  - 100BASE-T1 (BroadR-Reach)
  - 1000BASE-T1 (Gigabit Automotive)
  - 10BASE-T1S (Multidrop)
  - Multi-Gigabit
  - Standard 100BASE-TX / 1000BASE-T

Funktionen:
- Protokoll-Filter (IPv4/IPv6/ARP/VLAN/SOME-IP/DoIP/AVB)
- Physikalische Schicht + Capture-Modul Info
- Protokoll-Statistiken
- Ratenanzeige
"""

import logging
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QGroupBox,
    QTableView, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from ui.widgets.native_combo_box import ArrowComboBox

_log = logging.getLogger(__name__)
_MONO = QFont("Consolas", 9)

# Automotive Ethernet Protokoll-Registry
_PROTOCOLS = {
    'Alle': None,
    'IPv4 (0x0800)': 0x0800,
    'IPv6 (0x86DD)': 0x86DD,
    'ARP (0x0806)': 0x0806,
    'VLAN 802.1Q (0x8100)': 0x8100,
    'SOME/IP': 'SOME/IP',
    'DoIP (ISO 13400)': 'DoIP',
    'AVB/TSN (IEEE 1722)': 'AVB',
}

# Unterstuetzte Capture-Module und physikalische Schichten
_PHY_LAYERS = [
    ("100BASE-T1", "BroadR-Reach, IEEE 802.3bw", "CM 100 High"),
    ("1000BASE-T1", "Gigabit Automotive, IEEE 802.3bp", "CM 1000 High"),
    ("10BASE-T1S", "Multidrop, IEEE 802.3cg", "CM 10Base-T1S"),
    ("Multi-Gigabit", "2.5G/5G/10G Automotive", "CM MultiGigabit"),
    ("100BASE-TX", "Standard Fast Ethernet", "Standard NIC"),
    ("1000BASE-T", "Standard Gigabit Ethernet", "Standard NIC"),
]


class EthLivePage(QWidget):
    """Automotive Ethernet Live-Seite mit Protokoll-Info und Filter."""

    frame_for_bus_queue = pyqtSignal(tuple)

    def __init__(self, existing_eth_table: QTableView, parent=None):
        super().__init__(parent)
        self._existing_table = existing_eth_table
        self._bus_row_counters = None
        self._bus_index = 2
        self._last_bus_row_count = 0
        self._smoothed_rx_rate = 0.0
        self._smoothed_plp_rate = 0.0
        self._last_rate_time = 0.0
        self._last_plp_count = 0
        self._last_shown_src = ''
        self._proto_counts: Dict[str, int] = {}
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Konfigurationspanel ──
        self._config_widget = self._create_config_panel()
        layout.addWidget(self._config_widget)

        # ── RX-Bereich ──
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        # RX-Header
        rx_header_widget = QWidget()
        rx_header_widget.setFixedHeight(22)
        rx_header_widget.setStyleSheet(
            "background-color: #9C27B0; color: white;")
        rx_header_layout = QHBoxLayout(rx_header_widget)
        rx_header_layout.setContentsMargins(4, 0, 4, 0)
        rx_header_layout.setSpacing(8)

        self._rx_title = QLabel(
            "RX \u2014 Automotive Ethernet (TECMP/PLP)")
        self._rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(self._rx_title)
        rx_header_layout.addStretch()

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._rx_rate_label = QLabel("Eth: 0 Frames/s")
        self._rx_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)

        # ── Protokoll-Statistik (unterhalb RX-Tabelle) ──
        self._proto_stats_widget = QGroupBox("Protokoll-Statistik")
        self._proto_stats_widget.setStyleSheet(
            "QGroupBox { font-weight: bold; padding-top: 14px;"
            " margin-top: 4px; }")
        self._proto_stats_widget.setMaximumHeight(80)
        ps_layout = QHBoxLayout(self._proto_stats_widget)
        ps_layout.setSpacing(12)
        self._proto_stat_labels: Dict[str, QLabel] = {}
        for proto in ['IPv4', 'IPv6', 'ARP', 'VLAN', 'SOME/IP',
                       'DoIP', 'AVB', 'Andere']:
            lbl = QLabel(f"{proto}: 0")
            lbl.setFont(_MONO)
            ps_layout.addWidget(lbl)
            self._proto_stat_labels[proto] = lbl
        ps_layout.addStretch()
        rx_layout.addWidget(self._proto_stats_widget)

        layout.addWidget(rx_wrapper, 1)

        # ── Timer ──
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start(1000)

    def _create_config_panel(self) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # Toggle
        self._config_toggle = QPushButton("\u25bc Konfiguration")
        self._config_toggle.setStyleSheet(
            "text-align: left; padding: 2px 8px; font-weight: bold;"
            " font-size: 11px;")
        self._config_toggle.setFlat(True)
        self._config_toggle.setCheckable(True)
        self._config_toggle.setChecked(True)
        self._config_toggle.toggled.connect(self._on_config_toggle)
        wrapper_layout.addWidget(self._config_toggle)

        self._config_content = QWidget()
        cl = QVBoxLayout(self._config_content)
        cl.setContentsMargins(4, 2, 4, 4)
        cl.setSpacing(4)

        # Zeile 1: Protokoll-Filter + Capture-Modul Info
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        row1.addWidget(QLabel("Protokoll-Filter:"))
        self._proto_combo = ArrowComboBox()
        for name in _PROTOCOLS:
            self._proto_combo.addItem(name)
        self._proto_combo.setMinimumWidth(180)
        row1.addWidget(self._proto_combo)

        # Capture-Modul Anzeige
        self._cm_label = QLabel(
            "\u2139 Datenquelle: Technica CM / ViGEM Logger")
        self._cm_label.setStyleSheet(
            "color: #1565c0; font-size: 10px;")
        row1.addWidget(self._cm_label)

        row1.addStretch()
        cl.addLayout(row1)

        # Zeile 2: Physikalische Schichten Tabelle
        phy_group = QGroupBox(
            "Unterstuetzte Physikalische Schichten (Automotive Ethernet)")
        phy_group.setStyleSheet(
            "QGroupBox { font-weight: bold; font-size: 10px;"
            " padding-top: 14px; margin-top: 2px; }")
        phy_layout = QVBoxLayout(phy_group)
        phy_layout.setContentsMargins(4, 4, 4, 4)

        phy_table = QTableWidget()
        phy_table.setRowCount(len(_PHY_LAYERS))
        phy_table.setColumnCount(3)
        phy_table.setHorizontalHeaderLabels(
            ['Physikalische Schicht', 'Standard', 'Capture-Modul'])
        phy_table.setFont(QFont("Consolas", 8))
        phy_table.setMaximumHeight(140)
        phy_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        phy_table.verticalHeader().setVisible(False)
        phy_table.verticalHeader().setDefaultSectionSize(20)
        h = phy_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        phy_table.setColumnWidth(0, 120)
        phy_table.setColumnWidth(2, 140)

        for i, (phy, std, cm) in enumerate(_PHY_LAYERS):
            phy_table.setItem(i, 0, QTableWidgetItem(phy))
            phy_table.setItem(i, 1, QTableWidgetItem(std))
            cm_item = QTableWidgetItem(cm)
            cm_item.setForeground(QColor("#1565c0"))
            phy_table.setItem(i, 2, cm_item)

        phy_layout.addWidget(phy_table)
        cl.addWidget(phy_group)

        wrapper_layout.addWidget(self._config_content)
        return wrapper

    def _on_config_toggle(self, expanded: bool):
        self._config_content.setVisible(expanded)
        self._config_toggle.setText(
            "\u25bc Konfiguration" if expanded else "\u25b6 Konfiguration")

    # ── Protokoll zaehlen ──

    def count_protocol(self, proto_name: str):
        """Wird von wireshark_panel aufgerufen bei jedem gerouteten Frame."""
        self._proto_counts[proto_name] = (
            self._proto_counts.get(proto_name, 0) + 1)

    # ── Counter Refs ──

    def set_bus_row_counter_ref(self, counters: list, index: int):
        self._bus_row_counters = counters
        self._bus_index = index

    def set_plp_counter_ref(self, plp_pkt_counters: list,
                            plp_frame_counters: list, index: int):
        self._plp_counters = plp_pkt_counters
        self._plp_frame_counters = plp_frame_counters
        self._plp_index = index
        self._last_plp_count = 0

    def set_source_iface_ref(self, ifaces: list, protos: list, index: int):
        self._source_ifaces = ifaces
        self._source_protos = protos
        self._source_iface_index = index

    # ── Ratenberechnung ──

    def _update_rates(self):
        now = time.monotonic()
        elapsed = now - self._last_rate_time if self._last_rate_time > 0 else 1.0
        self._last_rate_time = now
        if elapsed <= 0:
            elapsed = 1.0
        alpha = 0.3

        # Ethernet Frame Rate
        if self._bus_row_counters is not None:
            current = self._bus_row_counters[self._bus_index]
            delta = current - self._last_bus_row_count
            self._last_bus_row_count = current
        else:
            delta = 0
        instant = delta / elapsed
        self._smoothed_rx_rate = (alpha * instant
                                  + (1 - alpha) * self._smoothed_rx_rate)
        self._rx_rate_label.setText(
            f"Eth: {round(self._smoothed_rx_rate)} Frames/s")

        # PLP Rate
        plp_delta = 0
        if hasattr(self, '_plp_counters') and self._plp_counters is not None:
            current_plp = self._plp_counters[self._plp_index]
            plp_delta = current_plp - self._last_plp_count
            self._last_plp_count = current_plp
        instant_plp = plp_delta / elapsed
        self._smoothed_plp_rate = (alpha * instant_plp
                                   + (1 - alpha) * self._smoothed_plp_rate)
        plp_display = round(self._smoothed_plp_rate)
        if round(self._smoothed_rx_rate) > 0 and plp_display < 1:
            plp_display = 1
        self._plp_rate_label.setText(f"PLP: {plp_display} Pkt/s")

        # Protokoll-Statistik aktualisieren
        for proto, lbl in self._proto_stat_labels.items():
            count = self._proto_counts.get(proto, 0)
            lbl.setText(f"{proto}: {count}")

        # RX-Titel
        if hasattr(self, '_source_ifaces'):
            idx = self._source_iface_index
            iface = self._source_ifaces[idx]
            proto = (self._source_protos[idx]
                     if hasattr(self, '_source_protos') else '')
            src_key = f"{iface}:{proto}"
            if src_key != self._last_shown_src and (iface or proto):
                self._last_shown_src = src_key
                parts = [x for x in (iface, proto) if x]
                self._rx_title.setText(
                    f"RX \u2014 Automotive Ethernet ({', '.join(parts)})")

    # ── Cleanup ──

    def cleanup(self):
        if self._rate_timer is not None:
            self._rate_timer.stop()
