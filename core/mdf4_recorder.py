"""MDF4 Recorder — Kontinuierliche Analog/Digital-Aufzeichnung in MDF4.

Verwendet asammdf fuer ASAM MDF 4.x Dateien.
Samples werden gebatcht (1000 Stueck) und dann per mdf.append() geschrieben.
"""

import logging
import time
from typing import Dict, List, Optional

import numpy as np

_log = logging.getLogger(__name__)

try:
    from asammdf import MDF, Signal
    MDF_AVAILABLE = True
except ImportError:
    MDF_AVAILABLE = False


class MDF4Recorder:
    """Zeichnet Analog/Digital-Signale in eine MDF4-Datei auf.

    Nutzung:
        rec = MDF4Recorder()
        rec.start('/tmp/measurement.mf4')
        rec.feed_analog(0, 1.234, 2.567)   # channel, timestamp, voltage
        rec.feed_digital(0, 1.234, 1)       # channel, timestamp, level
        rec.stop()
    """

    BATCH_SIZE = 1000

    def __init__(self):
        self._mdf: Optional['MDF'] = None
        self._path = ''
        self._recording = False
        self._start_time = 0.0

        # Batched sample buffers: channel → {timestamps: [], values: []}
        self._analog_buffers: Dict[int, dict] = {}
        self._digital_buffers: Dict[int, dict] = {}
        self._analog_count = 0
        self._digital_count = 0

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def sample_count(self) -> int:
        return self._analog_count + self._digital_count

    def start(self, path: str):
        """Startet die Aufzeichnung."""
        if not MDF_AVAILABLE:
            _log.error("asammdf nicht installiert")
            return
        self._path = path
        self._mdf = MDF(version='4.10')
        self._recording = True
        self._start_time = time.time()
        self._analog_buffers.clear()
        self._digital_buffers.clear()
        self._analog_count = 0
        self._digital_count = 0
        _log.info("MDF4 Recording gestartet: %s", path)

    def feed_analog(self, channel: int, timestamp: float, voltage: float):
        """Fuegt einen Analog-Sample hinzu."""
        if not self._recording:
            return
        buf = self._analog_buffers.setdefault(
            channel, {'timestamps': [], 'values': []})
        buf['timestamps'].append(timestamp)
        buf['values'].append(voltage)
        self._analog_count += 1

        if len(buf['timestamps']) >= self.BATCH_SIZE:
            self._flush_analog(channel)

    def feed_digital(self, channel: int, timestamp: float, level: int):
        """Fuegt einen Digital-Sample hinzu."""
        if not self._recording:
            return
        buf = self._digital_buffers.setdefault(
            channel, {'timestamps': [], 'values': []})
        buf['timestamps'].append(timestamp)
        buf['values'].append(float(level))
        self._digital_count += 1

        if len(buf['timestamps']) >= self.BATCH_SIZE:
            self._flush_digital(channel)

    def stop(self):
        """Stoppt die Aufzeichnung und speichert die Datei."""
        if not self._recording:
            return
        self._recording = False

        # Restliche Samples flushen
        for ch in list(self._analog_buffers):
            self._flush_analog(ch)
        for ch in list(self._digital_buffers):
            self._flush_digital(ch)

        # Datei speichern
        if self._mdf is not None:
            try:
                self._mdf.save(self._path, overwrite=True)
                _log.info("MDF4 gespeichert: %s (%d Samples)",
                          self._path, self.sample_count)
            except Exception as e:
                _log.error("MDF4 Speichern fehlgeschlagen: %s", e)
            finally:
                self._mdf.close()
                self._mdf = None

    def _flush_analog(self, channel: int):
        """Schreibt gebatchte Analog-Samples in die MDF-Datei."""
        buf = self._analog_buffers.get(channel)
        if not buf or not buf['timestamps']:
            return
        try:
            sig = Signal(
                samples=np.array(buf['values'], dtype=np.float64),
                timestamps=np.array(buf['timestamps'], dtype=np.float64),
                name=f"Analog_CH{channel}",
                unit="V",
            )
            self._mdf.append([sig])
        except Exception as e:
            _log.error("MDF4 Analog flush CH%d: %s", channel, e)
        buf['timestamps'].clear()
        buf['values'].clear()

    def _flush_digital(self, channel: int):
        """Schreibt gebatchte Digital-Samples in die MDF-Datei."""
        buf = self._digital_buffers.get(channel)
        if not buf or not buf['timestamps']:
            return
        try:
            sig = Signal(
                samples=np.array(buf['values'], dtype=np.float64),
                timestamps=np.array(buf['timestamps'], dtype=np.float64),
                name=f"Digital_CH{channel}",
                unit="",
            )
            self._mdf.append([sig])
        except Exception as e:
            _log.error("MDF4 Digital flush CH%d: %s", channel, e)
        buf['timestamps'].clear()
        buf['values'].clear()
