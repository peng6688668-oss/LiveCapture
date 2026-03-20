"""Analog Live-Seite fuer Echtzeit-Spannungsueberwachung (TECMP/PLP).

Analog-Daten kommen ueber TECMP/PLP Data Type 0x0020 (Analog).
Funktionen:
- Faltbares Konfigurationspanel (Kanalauswahl, Y-Achsenbereich, Schwellwerte)
- RX-Bereich: Bestehendes Analog-TableView (BusTableModel + FilterHeader)
- Echtzeit pyqtgraph Waveform (60s Fenster, Multi-Kanal Overlay)
- Schwellwert-Linien (obere/untere, rot gestrichelt)
- Cursor-Messung (DeltaV und DeltaT zwischen zwei vertikalen Cursor-Linien)
- Statistik-Zeile: Min/Max/Mittelwert/RMS pro Kanal
- Ratenanzeige (EMA-geglaettet)
"""

import logging
import math
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QComboBox, QTableView,
    QDoubleSpinBox, QCheckBox, QGroupBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from ui.widgets.native_combo_box import ArrowComboBox

try:
    import pyqtgraph as pg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False

_log = logging.getLogger(__name__)

_MONO = QFont("Consolas", 9)
_MONO_BOLD = QFont("Consolas", 9, QFont.Weight.Bold)

_MAX_SAMPLES = 15000  # 60s @ 250 Hz
_PLOT_WINDOW_S = 60.0

PLOT_COLORS = [
    '#e8560a', '#42a5f5', '#66bb6a', '#ffa726',
    '#ab47bc', '#ef5350', '#26c6da', '#d4e157',
]

_Y_RANGE_PRESETS = {
    "0-5V": (0.0, 5.0),
    "0-12V": (0.0, 12.0),
    "Auto": None,
}


class _ChannelBuffer:
    """Immutable-style per-channel sample storage.

    Data is appended to fixed-size deques; statistics are recomputed
    from the buffer contents on demand (no in-place mutation of stats).
    """

    __slots__ = ('timestamps', 'voltages')

    def __init__(self):
        self.timestamps: deque = deque(maxlen=_MAX_SAMPLES)
        self.voltages: deque = deque(maxlen=_MAX_SAMPLES)

    def append(self, ts: float, voltage: float) -> None:
        self.timestamps.append(ts)
        self.voltages.append(voltage)

    def stats(self) -> Dict[str, float]:
        """Return min/max/mean/rms as a new dict (no mutation)."""
        if not self.voltages:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "rms": 0.0}
        vals = list(self.voltages)
        n = len(vals)
        v_min = min(vals)
        v_max = max(vals)
        v_mean = sum(vals) / n
        v_rms = math.sqrt(sum(v * v for v in vals) / n)
        return {"min": v_min, "max": v_max, "mean": v_mean, "rms": v_rms}


class AnalogLivePage(QWidget):
    """Analog Live-Seite: Echtzeit-Spannungsmonitoring ueber TECMP/PLP.

    Nimmt das bestehende Analog-TableView (BusTableModel) als RX-Bereich
    und fuegt Konfiguration + Waveform-Plot + Statistik darueber/darunter.
    """

    frame_for_bus_queue = pyqtSignal(tuple)

    def __init__(self, existing_bus_table: QTableView, parent=None):
        super().__init__(parent)
        self._existing_table = existing_bus_table
        self._bus_row_counters: Optional[list] = None
        self._bus_index = 0
        self._last_bus_row_count = 0
        self._smoothed_rx_rate = 0.0
        self._smoothed_plp_rate = 0.0
        self._last_rate_time = 0.0
        self._last_plp_count = 0
        self._last_shown_src = ''

        # Channel buffers: channel_id -> _ChannelBuffer
        self._channels: Dict[int, _ChannelBuffer] = {}
        self._enabled_channels: List[int] = list(range(8))
        self._plot_curves: Dict[int, object] = {}

        # Threshold values
        self._threshold_upper = 4.5
        self._threshold_lower = 0.5
        self._thresholds_enabled = False

        self._init_ui()

    # ── UI Construction ──

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Collapsible config panel
        self._config_widget = self._create_config_panel()
        layout.addWidget(self._config_widget)

        # Main splitter: RX table + waveform
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #d0d0d8; height: 3px; }")

        # RX area
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        # RX header (orange)
        rx_header_widget = QWidget()
        rx_header_widget.setFixedHeight(22)
        rx_header_widget.setStyleSheet(
            "background-color: #FF9800; color: white;")
        rx_header_layout = QHBoxLayout(rx_header_widget)
        rx_header_layout.setContentsMargins(4, 0, 4, 0)
        rx_header_layout.setSpacing(8)

        self._rx_title = QLabel("RX \u2014 Analog Daten (TECMP/PLP)")
        self._rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(self._rx_title)
        rx_header_layout.addStretch()

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._rx_rate_label = QLabel("Analog: 0 Samples/s")
        self._rx_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)
        splitter.addWidget(rx_wrapper)

        # Waveform plot area
        plot_wrapper = QWidget()
        plot_layout = QVBoxLayout(plot_wrapper)
        plot_layout.setContentsMargins(0, 0, 0, 0)
        plot_layout.setSpacing(0)

        if PG_AVAILABLE:
            self._plot = pg.PlotWidget()
            self._plot.setBackground('#f5f5f7')
            self._plot.showGrid(x=True, y=True, alpha=0.3)
            self._plot.setLabel('bottom', 'Zeit', units='s')
            self._plot.setLabel('left', 'Spannung', units='V')
            self._plot.setMinimumHeight(150)
            self._plot.addLegend(offset=(10, 10))

            # Threshold lines (initially hidden)
            self._upper_line = pg.InfiniteLine(
                pos=self._threshold_upper, angle=0,
                pen=pg.mkPen('#F44336', width=1, style=Qt.PenStyle.DashLine),
                label=f"Upper: {self._threshold_upper:.2f}V",
                labelOpts={'color': '#F44336', 'position': 0.95},
            )
            self._lower_line = pg.InfiniteLine(
                pos=self._threshold_lower, angle=0,
                pen=pg.mkPen('#F44336', width=1, style=Qt.PenStyle.DashLine),
                label=f"Lower: {self._threshold_lower:.2f}V",
                labelOpts={'color': '#F44336', 'position': 0.95},
            )

            # Cursor measurement lines
            self._cursor_a = pg.InfiniteLine(
                pos=0, angle=90, movable=True,
                pen=pg.mkPen('#9C27B0', width=1, style=Qt.PenStyle.DashDotLine),
                label="A", labelOpts={'color': '#9C27B0', 'position': 0.95},
            )
            self._cursor_b = pg.InfiniteLine(
                pos=1, angle=90, movable=True,
                pen=pg.mkPen('#9C27B0', width=1, style=Qt.PenStyle.DashDotLine),
                label="B", labelOpts={'color': '#9C27B0', 'position': 0.90},
            )
            self._cursor_a.sigPositionChanged.connect(self._on_cursor_moved)
            self._cursor_b.sigPositionChanged.connect(self._on_cursor_moved)
            # Cursors initially hidden; toggled via config
            self._cursors_visible = False

            plot_layout.addWidget(self._plot, 1)
        else:
            self._plot = None
            plot_layout.addWidget(
                QLabel("pyqtgraph nicht installiert — Waveform deaktiviert"), 1)

        # Cursor measurement display
        self._cursor_info_label = QLabel("")
        self._cursor_info_label.setFont(_MONO)
        self._cursor_info_label.setStyleSheet("padding: 2px 8px;")
        self._cursor_info_label.hide()
        plot_layout.addWidget(self._cursor_info_label)

        splitter.addWidget(plot_wrapper)

        # Splitter proportions: table 40%, plot 60%
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        layout.addWidget(splitter, 1)

        # Statistics row
        stats_layout = QHBoxLayout()
        stats_layout.setContentsMargins(4, 2, 4, 2)
        stats_layout.setSpacing(12)
        self._stat_labels: Dict[str, QLabel] = {}
        for key, text in [
            ('min', 'Min: ---'),
            ('max', 'Max: ---'),
            ('mean', 'Mean: ---'),
            ('rms', 'RMS: ---'),
        ]:
            lbl = QLabel(text)
            lbl.setFont(_MONO)
            stats_layout.addWidget(lbl)
            self._stat_labels[key] = lbl
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # Rate + plot update timer
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._update_rates)
        self._rate_timer.start(1000)

        self._plot_timer = QTimer(self)
        self._plot_timer.timeout.connect(self._update_plot)
        self._plot_timer.start(250)

    def _create_config_panel(self) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # Toggle button
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

        # Channel select
        cl.addWidget(QLabel("Kanal:"))
        self._channel_combo = ArrowComboBox()
        self._channel_combo.addItems(
            ["Alle"] + [f"CH{i}" for i in range(8)])
        self._channel_combo.setMinimumWidth(80)
        self._channel_combo.currentTextChanged.connect(
            self._on_channel_changed)
        cl.addWidget(self._channel_combo)

        # Y-axis range
        cl.addWidget(QLabel("Y-Bereich:"))
        self._yrange_combo = ArrowComboBox()
        self._yrange_combo.addItems(list(_Y_RANGE_PRESETS.keys()))
        self._yrange_combo.setCurrentText("Auto")
        self._yrange_combo.setMinimumWidth(80)
        self._yrange_combo.currentTextChanged.connect(
            self._on_yrange_changed)
        cl.addWidget(self._yrange_combo)

        # Threshold inputs
        self._threshold_check = QCheckBox("Schwellwerte")
        self._threshold_check.toggled.connect(self._on_threshold_toggled)
        cl.addWidget(self._threshold_check)

        cl.addWidget(QLabel("Oben:"))
        self._upper_spin = QDoubleSpinBox()
        self._upper_spin.setRange(-50.0, 50.0)
        self._upper_spin.setValue(self._threshold_upper)
        self._upper_spin.setSuffix(" V")
        self._upper_spin.setDecimals(2)
        self._upper_spin.setSingleStep(0.1)
        self._upper_spin.setMinimumWidth(80)
        self._upper_spin.valueChanged.connect(self._on_upper_threshold_changed)
        cl.addWidget(self._upper_spin)

        cl.addWidget(QLabel("Unten:"))
        self._lower_spin = QDoubleSpinBox()
        self._lower_spin.setRange(-50.0, 50.0)
        self._lower_spin.setValue(self._threshold_lower)
        self._lower_spin.setSuffix(" V")
        self._lower_spin.setDecimals(2)
        self._lower_spin.setSingleStep(0.1)
        self._lower_spin.setMinimumWidth(80)
        self._lower_spin.valueChanged.connect(self._on_lower_threshold_changed)
        cl.addWidget(self._lower_spin)

        # Cursor toggle
        self._cursor_check = QCheckBox("Cursor")
        self._cursor_check.toggled.connect(self._on_cursor_toggled)
        cl.addWidget(self._cursor_check)

        # Info
        info_label = QLabel("Analog via TECMP 0x0020")
        info_label.setStyleSheet("color: #888; font-size: 10px;")
        cl.addWidget(info_label)

        cl.addStretch()
        wrapper_layout.addWidget(self._config_content)
        return wrapper

    # ── Config Handlers ──

    def _on_config_toggle(self, expanded: bool):
        self._config_content.setVisible(expanded)
        self._config_toggle.setText(
            "\u25bc Konfiguration" if expanded else "\u25b6 Konfiguration")

    def _on_channel_changed(self, text: str):
        if text == "Alle":
            self._enabled_channels = list(range(8))
        else:
            try:
                ch = int(text.replace("CH", ""))
                self._enabled_channels = [ch]
            except (ValueError, TypeError):
                self._enabled_channels = list(range(8))

    def _on_yrange_changed(self, text: str):
        if self._plot is None or not PG_AVAILABLE:
            return
        preset = _Y_RANGE_PRESETS.get(text)
        if preset is not None:
            self._plot.setYRange(preset[0], preset[1], padding=0.05)
            self._plot.enableAutoRange(axis='y', enable=False)
        else:
            self._plot.enableAutoRange(axis='y', enable=True)

    def _on_threshold_toggled(self, enabled: bool):
        self._thresholds_enabled = enabled
        if self._plot is None or not PG_AVAILABLE:
            return
        if enabled:
            self._plot.addItem(self._upper_line)
            self._plot.addItem(self._lower_line)
        else:
            self._plot.removeItem(self._upper_line)
            self._plot.removeItem(self._lower_line)

    def _on_upper_threshold_changed(self, value: float):
        self._threshold_upper = value
        if PG_AVAILABLE and self._plot is not None:
            self._upper_line.setPos(value)
            self._upper_line.label.setText(f"Upper: {value:.2f}V")

    def _on_lower_threshold_changed(self, value: float):
        self._threshold_lower = value
        if PG_AVAILABLE and self._plot is not None:
            self._lower_line.setPos(value)
            self._lower_line.label.setText(f"Lower: {value:.2f}V")

    def _on_cursor_toggled(self, enabled: bool):
        self._cursors_visible = enabled
        if self._plot is None or not PG_AVAILABLE:
            return
        if enabled:
            self._plot.addItem(self._cursor_a)
            self._plot.addItem(self._cursor_b)
            self._cursor_info_label.show()
            self._on_cursor_moved()
        else:
            self._plot.removeItem(self._cursor_a)
            self._plot.removeItem(self._cursor_b)
            self._cursor_info_label.hide()

    def _on_cursor_moved(self, _line=None):
        """Compute and display delta-V and delta-T between cursor lines."""
        if not self._cursors_visible or not PG_AVAILABLE:
            return
        t_a = self._cursor_a.value()
        t_b = self._cursor_b.value()
        delta_t = abs(t_b - t_a)

        # Find voltage at cursor positions for the first enabled channel
        v_a = self._voltage_at_time(t_a)
        v_b = self._voltage_at_time(t_b)
        if v_a is not None and v_b is not None:
            delta_v = abs(v_b - v_a)
            self._cursor_info_label.setText(
                f"Cursor A: {t_a:.3f}s / {v_a:.4f}V    "
                f"Cursor B: {t_b:.3f}s / {v_b:.4f}V    "
                f"\u0394t: {delta_t:.3f}s    \u0394V: {delta_v:.4f}V")
        else:
            self._cursor_info_label.setText(
                f"\u0394t: {delta_t:.3f}s    \u0394V: ---")

    def _voltage_at_time(self, t: float) -> Optional[float]:
        """Return interpolated voltage for the first enabled channel at time t."""
        for ch in self._enabled_channels:
            buf = self._channels.get(ch)
            if buf is None or len(buf.timestamps) < 2:
                continue
            ts_list = list(buf.timestamps)
            v_list = list(buf.voltages)
            if t <= ts_list[0]:
                return v_list[0]
            if t >= ts_list[-1]:
                return v_list[-1]
            # Binary search for bracket
            lo, hi = 0, len(ts_list) - 1
            while lo < hi - 1:
                mid = (lo + hi) // 2
                if ts_list[mid] <= t:
                    lo = mid
                else:
                    hi = mid
            # Linear interpolation
            dt = ts_list[hi] - ts_list[lo]
            if dt <= 0:
                return v_list[lo]
            frac = (t - ts_list[lo]) / dt
            return v_list[lo] + frac * (v_list[hi] - v_list[lo])
        return None

    # ── Data Feed ──

    def feed_analog_sample(self, channel: int, timestamp: float,
                           voltage: float) -> None:
        """Feed a single analog sample into the waveform buffer.

        Called from the protocol dispatch layer for TECMP data_type 0x0020.
        """
        if channel not in self._channels:
            self._channels[channel] = _ChannelBuffer()
        self._channels[channel].append(timestamp, voltage)

    # ── Plot Update ──

    def _update_plot(self):
        if not PG_AVAILABLE or self._plot is None:
            return
        if not self._channels:
            return

        now = time.monotonic()

        for ch_id in self._enabled_channels:
            buf = self._channels.get(ch_id)
            if buf is None or not buf.timestamps:
                # Remove stale curve
                if ch_id in self._plot_curves:
                    self._plot.removeItem(self._plot_curves[ch_id])
                    del self._plot_curves[ch_id]
                continue

            t_data = list(buf.timestamps)
            v_data = list(buf.voltages)

            # Create curve if not present
            if ch_id not in self._plot_curves:
                color = PLOT_COLORS[ch_id % len(PLOT_COLORS)]
                curve = self._plot.plot(
                    [], [],
                    pen=pg.mkPen(color, width=2),
                    name=f"CH{ch_id}",
                )
                self._plot_curves[ch_id] = curve

            self._plot_curves[ch_id].setData(t_data, v_data)

        # Remove curves for disabled channels
        for ch_id in list(self._plot_curves.keys()):
            if ch_id not in self._enabled_channels:
                self._plot.removeItem(self._plot_curves[ch_id])
                del self._plot_curves[ch_id]

        # Update statistics
        self._update_statistics()

        # Update cursor measurement if visible
        if self._cursors_visible:
            self._on_cursor_moved()

    def _update_statistics(self):
        """Refresh the Min/Max/Mean/RMS labels from channel buffers."""
        if not self._enabled_channels:
            return

        # Aggregate stats across enabled channels
        all_stats: List[Dict[str, float]] = []
        for ch_id in self._enabled_channels:
            buf = self._channels.get(ch_id)
            if buf is not None and buf.voltages:
                all_stats.append(buf.stats())

        if not all_stats:
            for lbl in self._stat_labels.values():
                lbl.setText(lbl.text().split(':')[0] + ': ---')
            return

        combined_min = min(s['min'] for s in all_stats)
        combined_max = max(s['max'] for s in all_stats)
        combined_mean = sum(s['mean'] for s in all_stats) / len(all_stats)
        combined_rms = math.sqrt(
            sum(s['rms'] ** 2 for s in all_stats) / len(all_stats))

        self._stat_labels['min'].setText(f"Min: {combined_min:.4f} V")
        self._stat_labels['max'].setText(f"Max: {combined_max:.4f} V")
        self._stat_labels['mean'].setText(f"Mean: {combined_mean:.4f} V")
        self._stat_labels['rms'].setText(f"RMS: {combined_rms:.4f} V")

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

    # ── Rate Calculation ──

    def _update_rates(self):
        now = time.monotonic()
        elapsed = now - self._last_rate_time if self._last_rate_time > 0 else 1.0
        self._last_rate_time = now
        if elapsed <= 0:
            elapsed = 1.0
        alpha = 0.3

        # Analog sample rate
        if self._bus_row_counters is not None:
            current = self._bus_row_counters[self._bus_index]
            delta = current - self._last_bus_row_count
            self._last_bus_row_count = current
        else:
            delta = 0
        instant = delta / elapsed
        self._smoothed_rx_rate = (
            alpha * instant + (1 - alpha) * self._smoothed_rx_rate)
        self._rx_rate_label.setText(
            f"Analog: {round(self._smoothed_rx_rate)} Samples/s")

        # PLP rate
        plp_delta = 0
        if hasattr(self, '_plp_counters') and self._plp_counters is not None:
            current_plp = self._plp_counters[self._plp_index]
            plp_delta = current_plp - self._last_plp_count
            self._last_plp_count = current_plp
        instant_plp = plp_delta / elapsed
        self._smoothed_plp_rate = (
            alpha * instant_plp + (1 - alpha) * self._smoothed_plp_rate)
        plp_display = round(self._smoothed_plp_rate)
        if round(self._smoothed_rx_rate) > 0 and plp_display < 1:
            plp_display = 1
        self._plp_rate_label.setText(f"PLP: {plp_display} Pkt/s")

        # RX title update with source info
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
                    f"RX \u2014 Analog Daten ({', '.join(parts)})")

    # ── Cleanup ──

    def cleanup(self):
        if self._rate_timer is not None:
            self._rate_timer.stop()
        if self._plot_timer is not None:
            self._plot_timer.stop()
        self._channels.clear()
        self._plot_curves.clear()
