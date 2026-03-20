"""FlexRay Live-Seite fuer RX-Monitoring mit FIBEX-Unterstuetzung.

FlexRay-Daten kommen ausschliesslich ueber TECMP/PLP (kein Linux-Treiber).
Funktionen:
- Faltbares Konfigurationspanel (FIBEX-Datei, Kanal-Filter)
- RX-Bereich: Bestehendes FlexRay-TableView (BusTableModel + FilterHeader)
- FIBEX Signal-Dekodierung bei Zeilen-Auswahl
- Ratenanzeige (PLP/TECMP Frames/s)
"""

import logging
import os
import time
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QComboBox, QHeaderView, QGroupBox, QTableView,
    QFileDialog,
)
from PyQt6.QtCore import Qt, QTimer, QSettings, pyqtSignal
from PyQt6.QtGui import QColor, QFont

# Standard QComboBox verwenden — globales Theme liefert Dreieckspfeil

_log = logging.getLogger(__name__)

_MONO = QFont("Consolas", 9)
_MONO_BOLD = QFont("Consolas", 9, QFont.Weight.Bold)


class FlexRayLivePage(QWidget):
    """FlexRay Live-Seite: RX-only Monitoring mit FIBEX Signal-Decode.

    Nimmt das bestehende FlexRay-TableView (BusTableModel) als RX-Bereich
    und fuegt Konfiguration + Signal-Detail darueber/darunter.
    """

    frame_for_bus_queue = pyqtSignal(tuple)

    def __init__(self, existing_flexray_table: QTableView, parent=None):
        super().__init__(parent)
        self._existing_table = existing_flexray_table
        self._bus_row_counters = None
        self._bus_index = 3
        self._last_bus_row_count = 0
        self._smoothed_rx_rate = 0.0
        self._smoothed_plp_rate = 0.0
        self._last_rate_time = 0.0
        self._last_plp_count = 0
        self._fibex = None
        self._fibex_name = ''
        self._last_shown_src = ''
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Faltbares Konfigurationspanel ──
        self._config_widget = self._create_config_panel()
        layout.addWidget(self._config_widget)

        # ── TX/RX Splitter ──
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #d0d0d8; height: 3px; }")

        # RX-Bereich
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        # RX-Header
        rx_header_widget = QWidget()
        rx_header_widget.setFixedHeight(22)
        rx_header_widget.setStyleSheet(
            "background-color: #F44336; color: white;")
        rx_header_layout = QHBoxLayout(rx_header_widget)
        rx_header_layout.setContentsMargins(4, 0, 4, 0)
        rx_header_layout.setSpacing(8)

        self._rx_title = QLabel("RX \u2014 FlexRay Daten (TECMP/PLP)")
        self._rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(self._rx_title)
        rx_header_layout.addStretch()

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._rx_rate_label = QLabel("FlexRay: 0 Frames/s")
        self._rx_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)

        # Signal-Detail-Tabelle (FIBEX Decode)
        self._signal_table = QTableWidget()
        self._signal_table.setColumnCount(6)
        self._signal_table.setHorizontalHeaderLabels(
            ['Signal', 'Rohwert', 'Physikalisch', 'Einheit', 'Min', 'Max'])
        self._signal_table.setFont(_MONO)
        self._signal_table.setMaximumHeight(120)
        self._signal_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._signal_table.horizontalHeader().setStretchLastSection(True)
        self._signal_table.verticalHeader().setVisible(False)
        self._signal_table.verticalHeader().setDefaultSectionSize(20)
        self._signal_table.hide()
        rx_layout.addWidget(self._signal_table)
        splitter.addWidget(rx_wrapper)

        try:
            self._existing_table.clicked.connect(self._on_rx_row_selected)
        except Exception:
            pass
        layout.addWidget(splitter, 1)

        # ── Raten-Timer ──
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start(1000)

        # ── FIBEX Auto-Load ──
        last_path = QSettings('ViGEM', 'LiveCapture').value(
            'fibex/last_path', '')
        if last_path and os.path.exists(last_path):
            self._do_load_fibex(last_path)

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
        # Kein lokales ComboBox-CSS — globales Theme uebernimmt
        cl = QHBoxLayout(self._config_content)
        cl.setContentsMargins(4, 2, 4, 2)
        cl.setSpacing(8)

        # Kanal-Filter
        cl.addWidget(QLabel("Kanal:"))
        self._channel_combo = QComboBox()
        self._channel_combo.addItems(["Alle", "A", "B"])
        self._channel_combo.setMaximumWidth(80)
        cl.addWidget(self._channel_combo)

        # FIBEX-Datei
        self._fibex_btn = QPushButton("FIBEX...")
        self._fibex_btn.setToolTip("FIBEX-Datei laden fuer Frame-Namen und Signale")
        self._fibex_btn.setMinimumWidth(80)
        self._fibex_btn.clicked.connect(self._load_fibex)
        cl.addWidget(self._fibex_btn)

        # Info-Label
        self._info_label = QLabel("FlexRay Daten nur via TECMP/PLP")
        self._info_label.setStyleSheet("color: #888; font-size: 10px;")
        cl.addWidget(self._info_label)

        cl.addStretch()
        wrapper_layout.addWidget(self._config_content)
        return wrapper

    def _on_config_toggle(self, expanded: bool):
        self._config_content.setVisible(expanded)
        self._config_toggle.setText(
            "\u25bc Konfiguration" if expanded else "\u25b6 Konfiguration")

    # ── FIBEX ──

    def _load_fibex(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "FIBEX-Datei laden", "",
            "FIBEX-Dateien (*.xml);;Alle Dateien (*)")
        if not path:
            return
        self._do_load_fibex(path)

    def _do_load_fibex(self, path: str):
        try:
            from core.fibex_parser import FibexDatabase
            db = FibexDatabase()
            db.load_file(path)
            self._fibex = db
            self._fibex_name = os.path.basename(path)
            self._fibex_btn.setText(f"FIBEX \u2714")
            self._fibex_btn.setToolTip(
                f"{self._fibex_name}\n"
                f"{len(db.frames)} Frames geladen")
            QSettings('ViGEM', 'LiveCapture').setValue(
                'fibex/last_path', path)
            _log.info("FIBEX geladen: %s (%d Frames)",
                      self._fibex_name, len(db.frames))
        except Exception as e:
            _log.error("FIBEX-Fehler: %s", e)

    def fibex_lookup(self, slot_id: int) -> str:
        """Gibt den Frame-Namen fuer eine Slot-ID zurueck."""
        if self._fibex is None:
            return ''
        try:
            frame = self._fibex.get_frame_by_slot(slot_id)
            return frame.name
        except (KeyError, Exception):
            return ''

    # ── Signal-Decode ──

    def _on_rx_row_selected(self, index):
        if self._fibex is None:
            self._signal_table.hide()
            return
        model = self._existing_table.model()
        if model is None:
            return
        # Slot-ID aus Spalte 3 (Slot)
        slot_str = model.data(model.index(index.row(), 3),
                              Qt.ItemDataRole.DisplayRole)
        # Daten-Hex aus Spalte 6
        data_str = model.data(model.index(index.row(), 6),
                              Qt.ItemDataRole.DisplayRole)
        if not slot_str or not data_str:
            self._signal_table.hide()
            return
        try:
            slot_id = int(slot_str)
        except (ValueError, TypeError):
            self._signal_table.hide()
            return
        try:
            frame = self._fibex.get_frame_by_slot(slot_id)
        except (KeyError, Exception):
            self._signal_table.hide()
            return
        if not frame.signals:
            self._signal_table.hide()
            return

        # Daten-Bytes parsen
        try:
            data_bytes = bytes.fromhex(data_str.replace(' ', ''))
        except (ValueError, Exception):
            self._signal_table.hide()
            return

        # Signal-Tabelle fuellen
        self._signal_table.setRowCount(len(frame.signals))
        for i, sig in enumerate(frame.signals):
            raw_val = self._extract_signal(data_bytes, sig.bit_position,
                                           sig.bit_size)
            phys_val = raw_val * sig.factor + sig.offset
            self._signal_table.setItem(i, 0, QTableWidgetItem(sig.name))
            self._signal_table.setItem(i, 1, QTableWidgetItem(str(raw_val)))
            self._signal_table.setItem(
                i, 2, QTableWidgetItem(f"{phys_val:.4g}"))
            self._signal_table.setItem(i, 3, QTableWidgetItem(sig.unit))
            self._signal_table.setItem(
                i, 4, QTableWidgetItem(f"{sig.min_val:.4g}"))
            self._signal_table.setItem(
                i, 5, QTableWidgetItem(f"{sig.max_val:.4g}"))
        self._signal_table.show()

    @staticmethod
    def _extract_signal(data: bytes, bit_pos: int, bit_size: int) -> int:
        """Extrahiert einen Signalwert aus Bytes (big-endian bit numbering)."""
        if bit_size == 0 or not data:
            return 0
        val = int.from_bytes(data, 'big')
        total_bits = len(data) * 8
        shift = total_bits - bit_pos - bit_size
        if shift < 0:
            return 0
        mask = (1 << bit_size) - 1
        return (val >> shift) & mask

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

        # FlexRay Frame Rate
        if self._bus_row_counters is not None:
            current = self._bus_row_counters[self._bus_index]
            delta = current - self._last_bus_row_count
            self._last_bus_row_count = current
        else:
            delta = 0
        instant = delta / elapsed
        self._smoothed_rx_rate = alpha * instant + (1 - alpha) * self._smoothed_rx_rate
        self._rx_rate_label.setText(
            f"FlexRay: {round(self._smoothed_rx_rate)} Frames/s")

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
                    f"RX \u2014 FlexRay Daten ({', '.join(parts)})")

    # ── Cleanup ──

    def cleanup(self):
        if self._rate_timer is not None:
            self._rate_timer.stop()
