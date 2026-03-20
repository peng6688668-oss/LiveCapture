"""Signal Loader — Laedt Signale aus MDF4/CSV fuer Playback.

Unterstuetzt:
  - MDF4 (.mf4, .mdf) via asammdf
  - CSV (.csv) mit Spalten: timestamp, channel, value
"""

import csv
import logging
from typing import Dict, List, Optional, Tuple

import numpy as np

_log = logging.getLogger(__name__)

try:
    from asammdf import MDF
    MDF_AVAILABLE = True
except ImportError:
    MDF_AVAILABLE = False


def load_signals(path: str) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    """Laedt Signale aus einer Datei.

    Returns: {signal_name: (timestamps, values)}
    """
    ext = path.lower().rsplit('.', 1)[-1] if '.' in path else ''

    if ext in ('mf4', 'mdf'):
        return _load_mdf4(path)
    elif ext == 'csv':
        return _load_csv(path)
    else:
        _log.error("Unbekanntes Dateiformat: %s", ext)
        return {}


def _load_mdf4(path: str) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    """Laedt alle Signale aus einer MDF4-Datei."""
    if not MDF_AVAILABLE:
        _log.error("asammdf nicht installiert")
        return {}

    signals = {}
    try:
        mdf = MDF(path)
        for group_idx in range(len(mdf.groups)):
            for ch_idx in range(len(mdf.groups[group_idx].channels)):
                try:
                    sig = mdf.get(group=group_idx, index=ch_idx)
                    if sig.samples is not None and len(sig.samples) > 0:
                        signals[sig.name] = (
                            np.array(sig.timestamps, dtype=np.float64),
                            np.array(sig.samples, dtype=np.float64),
                        )
                except Exception:
                    continue
        mdf.close()
    except Exception as e:
        _log.error("MDF4 laden: %s", e)

    _log.info("Signale geladen: %s (%d Kanaele)", path, len(signals))
    return signals


def _load_csv(path: str) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    """Laedt Signale aus CSV (Spalten: timestamp;channel;value oder Name-basiert)."""
    channels: Dict[str, dict] = {}

    try:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            headers = next(reader, None)
            if headers is None:
                return {}

            # Format 1: timestamp;channel;value
            if len(headers) == 3:
                for row in reader:
                    if len(row) < 3:
                        continue
                    try:
                        ts = float(row[0])
                        ch_name = row[1].strip()
                        val = float(row[2])
                        ch = channels.setdefault(
                            ch_name, {'timestamps': [], 'values': []})
                        ch['timestamps'].append(ts)
                        ch['values'].append(val)
                    except (ValueError, IndexError):
                        continue

            # Format 2: timestamp;CH0;CH1;CH2;...
            else:
                ch_names = [h.strip() for h in headers[1:]]
                for row in reader:
                    if len(row) < 2:
                        continue
                    try:
                        ts = float(row[0])
                        for i, name in enumerate(ch_names):
                            if i + 1 < len(row) and row[i + 1].strip():
                                val = float(row[i + 1])
                                ch = channels.setdefault(
                                    name, {'timestamps': [], 'values': []})
                                ch['timestamps'].append(ts)
                                ch['values'].append(val)
                    except (ValueError, IndexError):
                        continue

    except Exception as e:
        _log.error("CSV laden: %s", e)

    signals = {}
    for name, data in channels.items():
        signals[name] = (
            np.array(data['timestamps'], dtype=np.float64),
            np.array(data['values'], dtype=np.float64),
        )

    _log.info("CSV Signale geladen: %s (%d Kanaele)", path, len(signals))
    return signals
