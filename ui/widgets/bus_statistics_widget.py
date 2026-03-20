"""Bus Statistics Widget — Echtzeit-Diagramm fuer TX/RX/Fehler-Raten.

Zeigt 60-Sekunden-Zeitfenster mit pyqtgraph.
Aktualisiert alle 250ms.
"""

import time
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
)
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont

try:
    import pyqtgraph as pg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False

_MONO = QFont("Consolas", 9)
_MAX_POINTS = 240  # 60s bei 250ms Intervall


class BusStatisticsWidget(QWidget):
    """Echtzeit Bus-Statistik: TX/RX-Rate und Fehler ueber 60 Sekunden."""

    def __init__(self, bus_type: str = 'CAN', parent=None):
        super().__init__(parent)
        self._bus_type = bus_type

        self._timestamps = deque(maxlen=_MAX_POINTS)
        self._tx_rates = deque(maxlen=_MAX_POINTS)
        self._rx_rates = deque(maxlen=_MAX_POINTS)
        self._error_counts = deque(maxlen=_MAX_POINTS)

        self._tx_count = 0
        self._rx_count = 0
        self._err_count = 0
        self._last_tx = 0
        self._last_rx = 0
        self._last_err = 0
        self._start_time = time.time()

        self._tx_total = 0
        self._rx_total = 0
        self._err_total = 0
        self._tx_peak = 0.0
        self._rx_peak = 0.0

        self._init_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Header
        hdr = QHBoxLayout()
        hdr.setSpacing(8)
        title = QLabel(f"{self._bus_type} Statistik (60s)")
        title.setStyleSheet("font-weight: bold; font-size: 11px;")
        hdr.addWidget(title)

        clear_btn = QPushButton("Zuruecksetzen")
        clear_btn.setMinimumWidth(100)
        clear_btn.clicked.connect(self.clear_stats)
        hdr.addWidget(clear_btn)
        hdr.addStretch()
        layout.addLayout(hdr)

        # Plot
        if PG_AVAILABLE:
            self._plot = pg.PlotWidget()
            self._plot.setBackground('#f5f5f7')
            self._plot.showGrid(x=True, y=True, alpha=0.3)
            self._plot.setLabel('bottom', 'Zeit', units='s')
            self._plot.setLabel('left', 'Frames/s')
            self._plot.setMinimumHeight(120)
            self._plot.setMaximumHeight(200)

            self._tx_curve = self._plot.plot(
                [], [], pen=pg.mkPen('#4CAF50', width=2), name='TX')
            self._rx_curve = self._plot.plot(
                [], [], pen=pg.mkPen('#2196F3', width=2), name='RX')
            self._err_scatter = pg.ScatterPlotItem(
                [], [], brush=pg.mkBrush('#F44336'), size=6, name='Fehler')
            self._plot.addItem(self._err_scatter)
            self._plot.addLegend(offset=(10, 10))
            layout.addWidget(self._plot, 1)
        else:
            self._plot = None
            layout.addWidget(QLabel("pyqtgraph nicht installiert"), 1)

        # Info-Zeile
        info = QHBoxLayout()
        info.setSpacing(12)
        self._labels = {}
        for key, text in [
            ('tx_total', 'TX: 0'),
            ('rx_total', 'RX: 0'),
            ('err_total', 'Fehler: 0'),
            ('tx_avg', 'TX\u00d8: 0 f/s'),
            ('tx_peak', 'TX\u2191: 0 f/s'),
            ('rx_avg', 'RX\u00d8: 0 f/s'),
            ('rx_peak', 'RX\u2191: 0 f/s'),
        ]:
            lbl = QLabel(text)
            lbl.setFont(_MONO)
            info.addWidget(lbl)
            self._labels[key] = lbl
        info.addStretch()
        layout.addLayout(info)

    # ── Daten einspeisen ──

    def record_tx(self):
        self._tx_count += 1
        self._tx_total += 1

    def record_rx(self):
        self._rx_count += 1
        self._rx_total += 1

    def record_error(self):
        self._err_count += 1
        self._err_total += 1

    def clear_stats(self):
        self._timestamps.clear()
        self._tx_rates.clear()
        self._rx_rates.clear()
        self._error_counts.clear()
        self._tx_count = self._rx_count = self._err_count = 0
        self._last_tx = self._last_rx = self._last_err = 0
        self._tx_total = self._rx_total = self._err_total = 0
        self._tx_peak = self._rx_peak = 0.0
        self._start_time = time.time()
        self._update_labels()

    # ── Timer-Tick ──

    def _tick(self):
        elapsed = time.time() - self._start_time
        interval = 0.25  # 250ms

        tx_delta = self._tx_count - self._last_tx
        rx_delta = self._rx_count - self._last_rx
        err_delta = self._err_count - self._last_err
        self._last_tx = self._tx_count
        self._last_rx = self._rx_count
        self._last_err = self._err_count

        tx_rate = tx_delta / interval
        rx_rate = rx_delta / interval

        self._timestamps.append(elapsed)
        self._tx_rates.append(tx_rate)
        self._rx_rates.append(rx_rate)
        self._error_counts.append(err_delta)

        if tx_rate > self._tx_peak:
            self._tx_peak = tx_rate
        if rx_rate > self._rx_peak:
            self._rx_peak = rx_rate

        self._update_plot()
        self._update_labels()

    def _update_plot(self):
        if not PG_AVAILABLE or self._plot is None:
            return
        if not self._timestamps:
            return
        t = list(self._timestamps)
        self._tx_curve.setData(t, list(self._tx_rates))
        self._rx_curve.setData(t, list(self._rx_rates))
        err_t = [tt for tt, e in zip(t, self._error_counts) if e > 0]
        err_v = [float(e) for e in self._error_counts if e > 0]
        if err_t:
            self._err_scatter.setData(err_t, err_v)

    def _update_labels(self):
        self._labels['tx_total'].setText(f"TX: {self._tx_total}")
        self._labels['rx_total'].setText(f"RX: {self._rx_total}")
        self._labels['err_total'].setText(f"Fehler: {self._err_total}")

        n = len(self._tx_rates) or 1
        tx_avg = sum(self._tx_rates) / n if self._tx_rates else 0.0
        rx_avg = sum(self._rx_rates) / n if self._rx_rates else 0.0
        self._labels['tx_avg'].setText(f"TX\u00d8: {tx_avg:.0f} f/s")
        self._labels['tx_peak'].setText(f"TX\u2191: {self._tx_peak:.0f} f/s")
        self._labels['rx_avg'].setText(f"RX\u00d8: {rx_avg:.0f} f/s")
        self._labels['rx_peak'].setText(f"RX\u2191: {self._rx_peak:.0f} f/s")

    def cleanup(self):
        if self._timer:
            self._timer.stop()
