"""Digital/GPIO Live-Seite fuer Echtzeit-Logikanalyse (TECMP/PLP).

GPIO-Daten kommen ueber TECMP/PLP Data Type 0x000A (GPIO).
Funktionen:
- Faltbares Konfigurationspanel (Kanalauswahl, Flanken-Trigger)
- RX-Bereich: Bestehendes GPIO-TableView (BusTableModel + FilterHeader)
- Echtzeit pyqtgraph Logikanalysator (Step-Plot, gestapelte Kanaele)
- Statistik-Zeile: Frequenz/Tastverhaeltnis/Flankenanzahl/Pulsbreite
- Ratenanzeige (EMA-geglaettet)
"""

import logging
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QComboBox, QTableView,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

# Standard QComboBox verwenden — globales Theme liefert Dreieckspfeil

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

# Colors for logic levels
_HIGH_COLOR = '#66bb6a'   # green
_LOW_COLOR = '#9e9e9e'    # gray


class _DigitalChannelBuffer:
    """Per-channel digital sample storage.

    Keeps timestamps and levels in fixed-size deques.
    Statistics are recomputed from buffer contents on demand (immutable pattern).
    """

    __slots__ = ('timestamps', 'levels')

    def __init__(self):
        self.timestamps: deque = deque(maxlen=_MAX_SAMPLES)
        self.levels: deque = deque(maxlen=_MAX_SAMPLES)

    def append(self, ts: float, level: int) -> None:
        self.timestamps.append(ts)
        self.levels.append(level)

    def stats(self) -> Dict[str, object]:
        """Return frequency, duty_cycle, rising_edges, pulse_width as a new dict."""
        if len(self.timestamps) < 2:
            return {
                "frequency": 0.0,
                "duty_cycle": 0.0,
                "rising_edges": 0,
                "pulse_width_ms": 0.0,
            }

        ts_list = list(self.timestamps)
        lv_list = list(self.levels)
        n = len(lv_list)

        # Count rising edges
        rising_count = 0
        for i in range(1, n):
            if lv_list[i - 1] == 0 and lv_list[i] == 1:
                rising_count += 1

        # Total observation window
        total_time = ts_list[-1] - ts_list[0]
        if total_time <= 0:
            return {
                "frequency": 0.0,
                "duty_cycle": 0.0,
                "rising_edges": rising_count,
                "pulse_width_ms": 0.0,
            }

        # Frequency from rising edges
        frequency = rising_count / total_time if total_time > 0 else 0.0

        # Duty cycle: fraction of time spent high
        high_time = 0.0
        for i in range(1, n):
            if lv_list[i - 1] == 1:
                high_time += ts_list[i] - ts_list[i - 1]
        duty_cycle = (high_time / total_time * 100.0) if total_time > 0 else 0.0

        # Average pulse width (high pulses)
        pulse_widths: List[float] = []
        pulse_start: Optional[float] = None
        for i in range(n):
            if lv_list[i] == 1 and pulse_start is None:
                pulse_start = ts_list[i]
            elif lv_list[i] == 0 and pulse_start is not None:
                pulse_widths.append(ts_list[i] - pulse_start)
                pulse_start = None
        avg_pulse_ms = 0.0
        if pulse_widths:
            avg_pulse_ms = (sum(pulse_widths) / len(pulse_widths)) * 1000.0

        return {
            "frequency": frequency,
            "duty_cycle": duty_cycle,
            "rising_edges": rising_count,
            "pulse_width_ms": avg_pulse_ms,
        }


class DigitalLivePage(QWidget):
    """Digital/GPIO Live-Seite: Echtzeit-Logikanalyse ueber TECMP/PLP.

    Nimmt das bestehende GPIO-TableView (BusTableModel) als RX-Bereich
    und fuegt Konfiguration + Logikanalysator-Plot + Statistik darueber/darunter.
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

        # Channel buffers: channel_id -> _DigitalChannelBuffer
        self._channels: Dict[int, _DigitalChannelBuffer] = {}
        self._enabled_channels: List[int] = list(range(8))
        self._plot_curves: Dict[int, object] = {}

        # Edge trigger filter
        self._edge_trigger = "Both"  # Rising, Falling, Both

        self._init_ui()

    # ── UI Construction ──

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Collapsible config panel
        self._config_widget = self._create_config_panel()
        layout.addWidget(self._config_widget)

        # Main splitter: RX table + logic analyzer
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #d0d0d8; height: 3px; }")

        # RX area
        rx_wrapper = QWidget()
        rx_layout = QVBoxLayout(rx_wrapper)
        rx_layout.setContentsMargins(0, 0, 0, 0)
        rx_layout.setSpacing(0)

        # RX header (teal)
        rx_header_widget = QWidget()
        rx_header_widget.setFixedHeight(22)
        rx_header_widget.setStyleSheet(
            "background-color: #009688; color: white;")
        rx_header_layout = QHBoxLayout(rx_header_widget)
        rx_header_layout.setContentsMargins(4, 0, 4, 0)
        rx_header_layout.setSpacing(8)

        self._rx_title = QLabel("RX \u2014 Digital I/O (TECMP/PLP)")
        self._rx_title.setStyleSheet(
            "font-weight: bold; font-size: 11px; background: transparent;")
        rx_header_layout.addWidget(self._rx_title)
        rx_header_layout.addStretch()

        self._plp_rate_label = QLabel("PLP: 0 Pkt/s")
        self._plp_rate_label.setStyleSheet(
            "color: #FFD54F; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._plp_rate_label)

        self._rx_rate_label = QLabel("GPIO: 0 Samples/s")
        self._rx_rate_label.setStyleSheet(
            "color: #B9F6CA; font-weight: bold; font-size: 10px;"
            " background: transparent;")
        rx_header_layout.addWidget(self._rx_rate_label)

        rx_layout.addWidget(rx_header_widget)
        rx_layout.addWidget(self._existing_table)
        splitter.addWidget(rx_wrapper)

        # Logic analyzer plot area
        plot_wrapper = QWidget()
        plot_layout = QVBoxLayout(plot_wrapper)
        plot_layout.setContentsMargins(0, 0, 0, 0)
        plot_layout.setSpacing(0)

        if PG_AVAILABLE:
            self._plot = pg.PlotWidget()
            self._plot.setBackground('#f5f5f7')
            self._plot.showGrid(x=True, y=False, alpha=0.3)
            self._plot.setLabel('bottom', 'Zeit', units='s')
            self._plot.setLabel('left', 'Kanal')
            self._plot.setMinimumHeight(150)
            # Y-axis: each channel occupies a vertical band of height 1.0,
            # stacked from bottom (CH0) to top (CH7), with 0.2 gap.
            self._plot.setYRange(-0.5, 8 * 1.2 + 0.5, padding=0)
            self._plot.getAxis('left').setTicks(
                [[(i * 1.2 + 0.5, f"CH{i}") for i in range(8)]])

            plot_layout.addWidget(self._plot, 1)
        else:
            self._plot = None
            plot_layout.addWidget(
                QLabel("pyqtgraph nicht installiert — Logikanalysator deaktiviert"), 1)

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
            ('freq', 'Freq: ---'),
            ('duty', 'Duty: ---'),
            ('rising', 'Rising: ---'),
            ('pulse', 'Puls: ---'),
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
        self._channel_combo = QComboBox()
        self._channel_combo.addItems(
            ["Alle"] + [f"CH{i}" for i in range(8)])
        self._channel_combo.setMinimumWidth(80)
        self._channel_combo.currentTextChanged.connect(
            self._on_channel_changed)
        cl.addWidget(self._channel_combo)

        # Edge trigger
        cl.addWidget(QLabel("Flanke:"))
        self._edge_combo = QComboBox()
        self._edge_combo.addItems(["Both", "Rising", "Falling"])
        self._edge_combo.setMinimumWidth(90)
        self._edge_combo.currentTextChanged.connect(
            self._on_edge_changed)
        cl.addWidget(self._edge_combo)

        # Info
        info_label = QLabel("GPIO via TECMP 0x000A")
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

    def _on_edge_changed(self, text: str):
        self._edge_trigger = text

    # ── Data Feed ──

    def feed_digital_sample(self, channel: int, timestamp: float,
                            level: int) -> None:
        """Feed a single digital sample into the logic analyzer buffer.

        Called from the protocol dispatch layer for TECMP data_type 0x000A.
        Level: 0 = low, 1 = high.
        """
        if channel not in self._channels:
            self._channels[channel] = _DigitalChannelBuffer()

        buf = self._channels[channel]

        # Edge trigger filtering
        if self._edge_trigger != "Both" and buf.levels:
            prev = buf.levels[-1]
            if self._edge_trigger == "Rising" and not (prev == 0 and level == 1):
                # Still record the sample for continuous display, but mark
                # that it did not match the trigger. The plot always shows
                # the full waveform; the trigger filter only affects
                # highlighting (future extension).
                pass
            elif self._edge_trigger == "Falling" and not (prev == 1 and level == 0):
                pass

        buf.append(timestamp, level)

    # ── Plot Update ──

    def _update_plot(self):
        if not PG_AVAILABLE or self._plot is None:
            return
        if not self._channels:
            return

        for ch_id in self._enabled_channels:
            buf = self._channels.get(ch_id)
            if buf is None or not buf.timestamps:
                if ch_id in self._plot_curves:
                    self._plot.removeItem(self._plot_curves[ch_id])
                    del self._plot_curves[ch_id]
                continue

            t_data = list(buf.timestamps)
            lv_data = list(buf.levels)

            # Vertical offset: each channel at ch_id * 1.2
            offset = ch_id * 1.2
            y_data = [offset + lv * 0.8 for lv in lv_data]

            # Create curve if not present
            if ch_id not in self._plot_curves:
                color = PLOT_COLORS[ch_id % len(PLOT_COLORS)]
                curve = self._plot.plot(
                    [], [],
                    pen=pg.mkPen(color, width=2),
                    stepMode='left',
                    name=f"CH{ch_id}",
                )
                self._plot_curves[ch_id] = curve

            self._plot_curves[ch_id].setData(t_data, y_data)

        # Remove curves for disabled channels
        for ch_id in list(self._plot_curves.keys()):
            if ch_id not in self._enabled_channels:
                self._plot.removeItem(self._plot_curves[ch_id])
                del self._plot_curves[ch_id]

        # Update statistics
        self._update_statistics()

    def _update_statistics(self):
        """Refresh Frequency/Duty/Rising/Pulse labels from channel buffers."""
        if not self._enabled_channels:
            return

        all_stats: List[Dict[str, object]] = []
        for ch_id in self._enabled_channels:
            buf = self._channels.get(ch_id)
            if buf is not None and len(buf.timestamps) >= 2:
                all_stats.append(buf.stats())

        if not all_stats:
            for lbl in self._stat_labels.values():
                lbl.setText(lbl.text().split(':')[0] + ': ---')
            return

        # Show stats for first active channel, or aggregate
        if len(all_stats) == 1:
            s = all_stats[0]
            self._stat_labels['freq'].setText(
                f"Freq: {s['frequency']:.1f} Hz")
            self._stat_labels['duty'].setText(
                f"Duty: {s['duty_cycle']:.1f}%")
            self._stat_labels['rising'].setText(
                f"Rising: {s['rising_edges']}")
            self._stat_labels['pulse'].setText(
                f"Puls: {s['pulse_width_ms']:.2f} ms")
        else:
            # Multi-channel: show range
            freqs = [s['frequency'] for s in all_stats]
            duties = [s['duty_cycle'] for s in all_stats]
            total_rising = sum(s['rising_edges'] for s in all_stats)
            pulses = [s['pulse_width_ms'] for s in all_stats
                      if s['pulse_width_ms'] > 0]
            self._stat_labels['freq'].setText(
                f"Freq: {min(freqs):.1f}-{max(freqs):.1f} Hz")
            self._stat_labels['duty'].setText(
                f"Duty: {min(duties):.1f}-{max(duties):.1f}%")
            self._stat_labels['rising'].setText(
                f"Rising: {total_rising}")
            if pulses:
                self._stat_labels['pulse'].setText(
                    f"Puls: {min(pulses):.2f}-{max(pulses):.2f} ms")
            else:
                self._stat_labels['pulse'].setText("Puls: ---")

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

        # GPIO sample rate
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
            f"GPIO: {round(self._smoothed_rx_rate)} Samples/s")

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
                    f"RX \u2014 Digital I/O ({', '.join(parts)})")

    # ── Cleanup ──

    def cleanup(self):
        if self._rate_timer is not None:
            self._rate_timer.stop()
        if self._plot_timer is not None:
            self._plot_timer.stop()
        self._channels.clear()
        self._plot_curves.clear()
