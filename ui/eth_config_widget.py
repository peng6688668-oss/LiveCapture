"""Ethernet Live-Seite fuer RX-Monitoring.

Ethernet-Daten kommen ueber TECMP/PLP (EtherType 0x0080/0x0081).
Funktionen:
- Faltbares Konfigurationspanel (EtherType-Filter)
- RX-Bereich: Bestehendes Ethernet-TableView (BusTableModel + FilterHeader)
- Protokoll-Erkennung (IPv4/ARP/IPv6/SOME-IP/DoIP/VLAN)
- Ratenanzeige (PLP/TECMP Frames/s)
"""

import logging
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QComboBox, QHeaderView,
    QGroupBox, QTableView,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from ui.widgets.native_combo_box import NativeComboBox, NATIVE_COMBO_CSS

_log = logging.getLogger(__name__)

_MONO = QFont("Consolas", 9)

# EtherType Registry fuer Protokollnamen
_ETHERTYPE_NAMES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "VLAN", 0x88A8: "Q-in-Q",
    0x0000: "Alle",
}


class EthLivePage(QWidget):
    """Ethernet Live-Seite: RX-only Monitoring mit Protokoll-Erkennung.

    Nimmt das bestehende Ethernet-TableView (BusTableModel) als RX-Bereich
    und fuegt Konfiguration + Ratenanzeige hinzu.
    """

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
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Faltbares Konfigurationspanel ──
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

        self._rx_title = QLabel("RX \u2014 Ethernet Daten (TECMP/PLP)")
        self._rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(self._rx_title)
        rx_header_layout.addStretch()

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._rx_rate_label = QLabel("Ethernet: 0 Frames/s")
        self._rx_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)

        layout.addWidget(rx_wrapper, 1)

        # ── Raten-Timer ──
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start(1000)

    def _create_config_panel(self) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # Toggle-Button
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
        self._config_content.setStyleSheet(NATIVE_COMBO_CSS)
        cl = QHBoxLayout(self._config_content)
        cl.setContentsMargins(4, 2, 4, 2)
        cl.setSpacing(8)

        # EtherType-Filter
        cl.addWidget(QLabel("EtherType-Filter:"))
        self._ethertype_combo = NativeComboBox()
        self._ethertype_combo.addItem("Alle", 0x0000)
        self._ethertype_combo.addItem("IPv4 (0x0800)", 0x0800)
        self._ethertype_combo.addItem("ARP (0x0806)", 0x0806)
        self._ethertype_combo.addItem("IPv6 (0x86DD)", 0x86DD)
        self._ethertype_combo.addItem("VLAN (0x8100)", 0x8100)
        self._ethertype_combo.setMaximumWidth(180)
        cl.addWidget(self._ethertype_combo)

        # Info-Label
        self._info_label = QLabel("Ethernet Daten via TECMP/PLP")
        self._info_label.setStyleSheet("color: #888; font-size: 10px;")
        cl.addWidget(self._info_label)

        cl.addStretch()
        wrapper_layout.addWidget(self._config_content)
        return wrapper

    def _on_config_toggle(self, expanded: bool):
        self._config_content.setVisible(expanded)
        self._config_toggle.setText(
            "\u25bc Konfiguration" if expanded else "\u25b6 Konfiguration")

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
        self._smoothed_rx_rate = alpha * instant + (1 - alpha) * self._smoothed_rx_rate
        self._rx_rate_label.setText(
            f"Ethernet: {round(self._smoothed_rx_rate)} Frames/s")

        # PLP Rate
        plp_delta = 0
        if hasattr(self, '_plp_counters') and self._plp_counters is not None:
            current_plp = self._plp_counters[self._plp_index]
            plp_delta = current_plp - self._last_plp_count
            self._last_plp_count = current_plp
        instant_plp = plp_delta / elapsed
        self._smoothed_plp_rate = alpha * instant_plp + (1 - alpha) * self._smoothed_plp_rate
        plp_display = round(self._smoothed_plp_rate)
        if round(self._smoothed_rx_rate) > 0 and plp_display < 1:
            plp_display = 1
        self._plp_rate_label.setText(f"PLP: {plp_display} Pkt/s")

        # RX-Titel aktualisieren
        if hasattr(self, '_source_ifaces'):
            idx = self._source_iface_index
            iface = self._source_ifaces[idx]
            proto = self._source_protos[idx] if hasattr(
                self, '_source_protos') else ''
            src_key = f"{iface}:{proto}"
            if src_key != self._last_shown_src and (iface or proto):
                self._last_shown_src = src_key
                parts = [x for x in (iface, proto) if x]
                self._rx_title.setText(
                    f"RX \u2014 Ethernet Daten ({', '.join(parts)})")

    # ── Cleanup ──

    def cleanup(self):
        if self._rate_timer is not None:
            self._rate_timer.stop()
