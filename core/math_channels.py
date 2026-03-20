"""Math Channels — Berechnungsfunktionen fuer Analog/Digital-Signale.

Analog: FFT, Ableitung, Integral, gleitender RMS
Digital: AND, OR, XOR Logik-Operationen

Alle Funktionen sind rein (pure functions) — keine Seiteneffekte,
Eingabe-Arrays werden nicht veraendert.
"""

import numpy as np
from typing import Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Analog Math
# ═══════════════════════════════════════════════════════════════════════════

def compute_fft(voltages: np.ndarray, sample_rate: float
                ) -> Tuple[np.ndarray, np.ndarray]:
    """Berechnet FFT Frequenzspektrum.

    Returns: (frequencies, magnitudes) — beide als 1D-Arrays
    """
    n = len(voltages)
    if n < 2 or sample_rate <= 0:
        return np.array([]), np.array([])

    # Fensterung (Hanning) fuer reduziertes Spectral Leakage
    window = np.hanning(n)
    windowed = voltages * window

    fft_vals = np.fft.rfft(windowed)
    magnitudes = 2.0 * np.abs(fft_vals) / n
    frequencies = np.fft.rfftfreq(n, d=1.0 / sample_rate)

    return frequencies, magnitudes


def compute_derivative(timestamps: np.ndarray, voltages: np.ndarray
                       ) -> Tuple[np.ndarray, np.ndarray]:
    """Berechnet die zeitliche Ableitung dV/dt.

    Returns: (timestamps_mid, dv_dt) — Mittelpunkte der Zeitintervalle
    """
    if len(timestamps) < 2:
        return np.array([]), np.array([])

    dt = np.diff(timestamps)
    dv = np.diff(voltages)

    # Division durch Null vermeiden
    dt_safe = np.where(dt == 0, 1e-9, dt)
    dv_dt = dv / dt_safe
    t_mid = (timestamps[:-1] + timestamps[1:]) / 2

    return t_mid, dv_dt


def compute_integral(timestamps: np.ndarray, voltages: np.ndarray
                     ) -> Tuple[np.ndarray, np.ndarray]:
    """Berechnet das kumulative Integral (Trapezregel).

    Returns: (timestamps, cumulative_integral)
    """
    if len(timestamps) < 2:
        return timestamps.copy(), np.zeros_like(voltages)

    dt = np.diff(timestamps)
    avg_v = (voltages[:-1] + voltages[1:]) / 2
    increments = avg_v * dt
    cumulative = np.concatenate(([0.0], np.cumsum(increments)))

    return timestamps.copy(), cumulative


def compute_rms_filter(voltages: np.ndarray, window_size: int = 50
                       ) -> np.ndarray:
    """Berechnet gleitenden RMS-Wert.

    Returns: rms_values (gleiche Laenge wie Eingabe)
    """
    if len(voltages) == 0 or window_size < 1:
        return np.array([])

    n = len(voltages)
    result = np.zeros(n)
    squared = voltages ** 2

    # Kumulative Summe fuer effiziente Fenster-Berechnung
    cumsum = np.concatenate(([0.0], np.cumsum(squared)))
    for i in range(n):
        start = max(0, i - window_size + 1)
        count = i - start + 1
        mean_sq = (cumsum[i + 1] - cumsum[start]) / count
        result[i] = np.sqrt(mean_sq)

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Digital Logic
# ═══════════════════════════════════════════════════════════════════════════

def compute_logic_and(levels_a: np.ndarray,
                      levels_b: np.ndarray) -> np.ndarray:
    """Logisches AND zweier Digital-Kanaele."""
    min_len = min(len(levels_a), len(levels_b))
    return (levels_a[:min_len].astype(int)
            & levels_b[:min_len].astype(int)).astype(float)


def compute_logic_or(levels_a: np.ndarray,
                     levels_b: np.ndarray) -> np.ndarray:
    """Logisches OR zweier Digital-Kanaele."""
    min_len = min(len(levels_a), len(levels_b))
    return (levels_a[:min_len].astype(int)
            | levels_b[:min_len].astype(int)).astype(float)


def compute_logic_xor(levels_a: np.ndarray,
                      levels_b: np.ndarray) -> np.ndarray:
    """Logisches XOR zweier Digital-Kanaele."""
    min_len = min(len(levels_a), len(levels_b))
    return (levels_a[:min_len].astype(int)
            ^ levels_b[:min_len].astype(int)).astype(float)
