"""Echtzeit-ISP-Pipeline für Live-Vorschau.

Optimiert für 30 FPS bei 4K RAW12 Eingang auf CPU (kein GPU).
Strategie: Downscale-First → ISP auf reduzierter Auflösung.
"""

import logging

import cv2
import numpy as np

logger = logging.getLogger(__name__)


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _build_wb_gamma_lut_8bit(gain: float) -> np.ndarray:
    """Fused White-Balance + sRGB-Gamma LUT: uint8 → uint8 (256 Einträge).

    Schnellere Alternative zur 65536-Eintrags-LUT für Vorschau-Qualität.
    """
    lut_lin = np.arange(256, dtype=np.float64) / 255.0
    lut_lin = np.clip(lut_lin * gain, 0.0, 1.0)
    lut_gam = np.where(
        lut_lin <= 0.0031308,
        12.92 * lut_lin,
        1.055 * np.power(lut_lin, 1.0 / 2.4) - 0.055)
    return np.clip(lut_gam * 255.0, 0, 255).astype(np.uint8)


def _apply_clahe_gainmap(v_ch: np.ndarray, clip_limit: float,
                         tile_grid: tuple = (8, 8)) -> np.ndarray:
    """CLAHE via 4× downsampled Gain-Map (16× weniger Pixel).

    Statt CLAHE direkt auf dem Vollbild wird auf einem 4× verkleinertem
    Bild gerechnet, eine Gain-Map erstellt und hochskaliert.
    """
    h, w = v_ch.shape[:2]
    v_small = cv2.resize(v_ch, (max(w // 4, 1), max(h // 4, 1)),
                         interpolation=cv2.INTER_AREA)
    clahe = cv2.createCLAHE(clipLimit=clip_limit, tileGridSize=tile_grid)
    v_clahe_small = clahe.apply(v_small)
    gain_small = (v_clahe_small.astype(np.float32)
                  / np.maximum(v_small.astype(np.float32), 1.0))
    gain_full = cv2.resize(gain_small, (w, h),
                           interpolation=cv2.INTER_LINEAR)
    return np.clip(v_ch.astype(np.float32) * gain_full,
                   0, 255).astype(np.uint8)


def _unpack_raw12_lines(line_list: list, width: int, n_lines: int
                        ) -> np.ndarray:
    """Vektorisierte RAW12-Entpackung: 3 Bytes → 2 Pixel (12 Bit).

    Parameter:
        line_list:  Liste von bytes-Objekten (eine pro Zeile)
        width:      Pixel-Breite (2 Pixel pro 3 Bytes)
        n_lines:    Anzahl der zu entpackenden Zeilen (= len(line_list))
    """
    image = np.zeros((n_lines, width), dtype=np.uint16)
    if n_lines == 0:
        return image

    bpl = len(line_list[0])
    n_groups = bpl // 3
    if n_groups == 0:
        return image

    expected_len = n_groups * 3

    # Fast-Path: alle Zeilen → ein einziges Array
    try:
        raw_flat = np.frombuffer(
            b''.join(line_list[r][:expected_len] for r in range(n_lines)),
            dtype=np.uint8)
        raw_all = raw_flat.reshape(n_lines, n_groups, 3)
    except (ValueError, IndexError):
        raw_all = np.zeros((n_lines, expected_len), dtype=np.uint8)
        for r in range(n_lines):
            lb = line_list[r]
            valid_bytes = min(len(lb), expected_len)
            raw_all[r, :valid_bytes] = np.frombuffer(
                lb[:valid_bytes], dtype=np.uint8)
        raw_all = raw_all.reshape(n_lines, n_groups, 3)

    b0 = raw_all[:, :, 0].astype(np.uint16)
    b1 = raw_all[:, :, 1].astype(np.uint16)
    b2 = raw_all[:, :, 2].astype(np.uint16)
    p1 = (b0 << 4) | (b1 & 0x0F)
    p2 = (b2 << 4) | (b1 >> 4)

    pixels_2d = np.empty((n_lines, n_groups * 2), dtype=np.uint16)
    pixels_2d[:, 0::2] = p1
    pixels_2d[:, 1::2] = p2

    valid_w = min(n_groups * 2, width)
    image[:n_lines, :valid_w] = pixels_2d[:, :valid_w]
    return image


def _detect_dual_gain(image: np.ndarray, sensor_cache: dict) -> str:
    """Erkennt Dual-Gain-Achse (col/row/none). Gecacht nach Frame 1."""
    cached = sensor_cache.get('dg_gain_axis')
    if cached is not None:
        return cached

    # Spalten-Vergleich (subsampled)
    even_cols = image[::8, 0::2]
    odd_cols = image[::8, 1::2]
    mean_even_col = float(np.mean(even_cols))
    mean_odd_col = float(np.mean(odd_cols))
    if mean_odd_col <= 0:
        mean_odd_col = 1.0
    col_ratio = mean_even_col / mean_odd_col
    col_dev = max(col_ratio, 1.0 / col_ratio) if col_ratio > 0 else 1.0

    # Zeilen-Vergleich (subsampled)
    even_rows = image[0::2, ::8]
    odd_rows = image[1::2, ::8]
    mean_even_row = float(np.mean(even_rows))
    mean_odd_row = float(np.mean(odd_rows))
    if mean_odd_row <= 0:
        mean_odd_row = 1.0
    row_ratio = mean_even_row / mean_odd_row
    row_dev = max(row_ratio, 1.0 / row_ratio) if row_ratio > 0 else 1.0

    # Interleave-Metrik auf Subsample
    def _interleave_metric(ch_a, ch_b):
        min_h = min(ch_a.shape[0], ch_b.shape[0])
        min_w = min(ch_a.shape[1], ch_b.shape[1])
        a = ch_a[:min_h, :min_w].astype(np.float32)
        b = ch_b[:min_h, :min_w].astype(np.float32)
        std_diff = np.std(a - b)
        std_avg = np.std((a + b) / 2.0)
        if std_avg < 1.0:
            return 1.0
        return std_diff / std_avg

    # Nur auf subsampled Daten (viel schneller)
    sub_even_c = image[::4, 0::2]
    sub_odd_c = image[::4, 1::2]
    sub_even_r = image[0::2, ::4]
    sub_odd_r = image[1::2, ::4]
    col_il = _interleave_metric(sub_even_c, sub_odd_c)
    row_il = _interleave_metric(sub_even_r, sub_odd_r)

    INTERLEAVE_THRESH = 0.35
    if col_dev > 1.05 and col_dev >= row_dev:
        gain_axis = 'col'
    elif row_dev > 1.05 and row_dev > col_dev:
        gain_axis = 'row'
    elif col_il < INTERLEAVE_THRESH and col_il < row_il:
        gain_axis = 'col'
    elif row_il < INTERLEAVE_THRESH and row_il < col_il:
        gain_axis = 'row'
    else:
        gain_axis = 'none'

    sensor_cache['dg_gain_axis'] = gain_axis
    return gain_axis


def _detect_bayer_pattern(img_16: np.ndarray, sensor_cache: dict) -> int:
    """Auto-Erkennung des Bayer-Patterns (gecacht nach Frame 1)."""
    cached = sensor_cache.get('dg_bayer_pattern')
    if cached is not None:
        return cached

    patterns = [
        (cv2.COLOR_BayerBG2BGR, 'BG'),
        (cv2.COLOR_BayerGB2BGR, 'GB'),
        (cv2.COLOR_BayerRG2BGR, 'RG'),
        (cv2.COLOR_BayerGR2BGR, 'GR'),
    ]
    crop_h = min(256, img_16.shape[0])
    crop_w = min(256, img_16.shape[1])
    cy, cx = img_16.shape[0] // 2, img_16.shape[1] // 2
    y0 = (cy - crop_h // 2) & ~1
    x0 = (cx - crop_w // 2) & ~1
    crop = img_16[y0:y0 + crop_h, x0:x0 + crop_w]

    best_sat = -1.0
    best_code = cv2.COLOR_BayerBG2BGR
    for code, _name in patterns:
        try:
            bgr_t = cv2.cvtColor(crop, code)
            hsv_t = cv2.cvtColor(
                (bgr_t >> 8).astype(np.uint8), cv2.COLOR_BGR2HSV)
            mean_sat = float(np.mean(hsv_t[:, :, 1]))
            if mean_sat > best_sat:
                best_sat = mean_sat
                best_code = code
        except cv2.error:
            continue

    sensor_cache['dg_bayer_pattern'] = best_code
    return best_code


# ── Hauptpipeline: RAW12 → BGR ──────────────────────────────────────────────

def raw12_to_bgr_preview(lines: list, width: int, height: int,
                         sensor_cache: dict,
                         dual_gain_mode: str = 'auto') -> np.ndarray:
    """RAW12 → BGR (max 1920×1080) für Echtzeit-Vorschau.

    Pipeline-Stufen:
      1. RAW12 entpacken (ggf. halbe Zeilen bei non-DG)
      2. Dual-Gain erkennen + HCG extrahieren (oder Bayer-Subsample)
      3. Black-Level / White-Point (subsampled Percentile)
      4. Demosaic (cv2.cvtColor) auf uint16
      5. Shift auf uint8 + WB+Gamma (gecachte 256-Eintrags-LUTs)
      6. CLAHE Gain-Map (4× downsampled)

    Parameter:
        lines:           Liste von bytes (eine pro CSI-2-Zeile)
        width:           Pixel-Breite (z.B. 3840)
        height:          Pixel-Höhe (z.B. 2160)
        sensor_cache:    dict für gecachte Sensor-Metadaten (wird befüllt)
        dual_gain_mode:  'auto', 'hcg', 'lcg' oder 'off'
    """
    if not lines or width <= 0 or height <= 0:
        return np.zeros((2, 2, 3), dtype=np.uint8)

    # ── Gain-Axis aus Cache lesen (wenn vorhanden) ──
    cached_axis = sensor_cache.get('dg_gain_axis')

    # ── 1. RAW12 entpacken ──
    # Optimierung: Bei gecachtem non-DG und breitem Bild nur jede 2. Zeile
    need_subsample_rows = (
        cached_axis == 'none' and width > 1920
        and dual_gain_mode != 'off')
    if need_subsample_rows:
        # Nur gerade Zeilen entpacken (Bayer-Zeile 0, 2, 4, ...)
        even_lines = lines[0::2]
        image = _unpack_raw12_lines(even_lines, width, len(even_lines))
        # Nur noch Spalten-Subsample nötig
        hcg = image[:, 0::2]
    elif cached_axis == 'none' and dual_gain_mode == 'off' and width > 1920:
        even_lines = lines[0::2]
        image = _unpack_raw12_lines(even_lines, width, len(even_lines))
        hcg = image[:, 0::2]
    else:
        image = _unpack_raw12_lines(lines, width, min(len(lines), height))

        # ── 2. Dual-Gain → HCG extrahieren ──
        if dual_gain_mode == 'off':
            gain_axis = 'none'
        else:
            gain_axis = _detect_dual_gain(image, sensor_cache)

        if gain_axis == 'col':
            hcg = image[:, 0::2]
        elif gain_axis == 'row':
            hcg = image[0::2, :]
        else:
            if width > 1920:
                hcg = image[0::2, 0::2]
            else:
                hcg = image

    # ── 3. Black-Level / White-Point (subsampled Percentile) ──
    cached_bl = sensor_cache.get('dg_black_level')
    if cached_bl is not None:
        black_level = cached_bl
    else:
        sample = hcg[::4, ::4]
        sample = sample[sample > 0]
        black_level = float(np.percentile(sample, 1)) \
            if len(sample) > 0 else 0.0
        sensor_cache['dg_black_level'] = black_level

    ch = hcg.astype(np.float32) - black_level
    np.clip(ch, 0, None, out=ch)

    ch_sub = ch[::4, ::4]
    nonzero = ch_sub[ch_sub > 0]
    white_pt = float(np.percentile(nonzero, 99.9)) \
        if len(nonzero) > 0 else 1.0
    if white_pt < 1.0:
        white_pt = 1.0
    ch *= (65535.0 / white_pt)
    np.clip(ch, 0, 65535, out=ch)
    img_16 = ch.astype(np.uint16)

    # ── 4. Sensor-Klassifikation (Mono/Bayer) ──
    is_mono = sensor_cache.get('dg_is_mono')
    if is_mono is None:
        active = hcg[hcg > 50]
        if len(active) > 100:
            def _safe_mean(arr):
                m = arr[arr > 50]
                return float(np.mean(m)) if len(m) > 0 else 0.0
            q00 = _safe_mean(hcg[0::2, 0::2])
            q01 = _safe_mean(hcg[0::2, 1::2])
            q10 = _safe_mean(hcg[1::2, 0::2])
            q11 = _safe_mean(hcg[1::2, 1::2])
            row_even = (q00 + q01) / 2.0
            row_odd = (q10 + q11) / 2.0
            row_max = max(row_even, row_odd)
            row_diff = abs(row_even - row_odd) / row_max \
                if row_max > 0 else 0
            is_mono = row_diff < 0.005
        else:
            is_mono = True
        sensor_cache['dg_is_mono'] = is_mono

    # ── 5. Demosaic auf uint16 ──
    if is_mono:
        bgr_16 = cv2.cvtColor(img_16, cv2.COLOR_GRAY2BGR)
    else:
        pattern = _detect_bayer_pattern(img_16, sensor_cache)
        try:
            bgr_16 = cv2.cvtColor(img_16, pattern)
        except cv2.error:
            bgr_16 = cv2.cvtColor(img_16, cv2.COLOR_GRAY2BGR)

    # ── 6. uint16→uint8 + WB+Gamma (256-Eintrags-LUT, ~3× schneller) ──
    bgr_8 = (bgr_16 >> 8).astype(np.uint8)

    wb_sub = bgr_8[::4, ::4]
    gm = float(np.mean(wb_sub[:, :, 1]))
    bm = float(np.mean(wb_sub[:, :, 0]))
    rm = float(np.mean(wb_sub[:, :, 2]))
    gain_b = (gm / bm) if bm > 0 else 1.0
    gain_r = (gm / rm) if rm > 0 else 1.0

    # LUT-Cache: nur neu bauen wenn Gain > 5% abweicht
    cached_wb = sensor_cache.get('_wb_gamma_luts')
    rebuild = True
    if cached_wb is not None:
        pg = cached_wb['gains']
        if (abs(gain_b - pg[0]) / max(pg[0], 1e-6) < 0.05
                and abs(gain_r - pg[2]) / max(pg[2], 1e-6) < 0.05):
            lut_b, lut_g, lut_r = cached_wb['luts']
            rebuild = False
    if rebuild:
        lut_b = _build_wb_gamma_lut_8bit(gain_b)
        lut_g = _build_wb_gamma_lut_8bit(1.0)
        lut_r = _build_wb_gamma_lut_8bit(gain_r)
        sensor_cache['_wb_gamma_luts'] = {
            'gains': [gain_b, 1.0, gain_r],
            'luts': [lut_b, lut_g, lut_r]}

    # cv2.LUT ist ~5× schneller als NumPy-Indexing für uint8
    bgr_b = cv2.LUT(bgr_8[:, :, 0], lut_b)
    bgr_g = cv2.LUT(bgr_8[:, :, 1], lut_g)
    bgr_r = cv2.LUT(bgr_8[:, :, 2], lut_r)
    bgr = cv2.merge([bgr_b, bgr_g, bgr_r])

    # ── 7. CLAHE Gain-Map ──
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    h_ch, s_ch, v_ch = hsv[:, :, 0], hsv[:, :, 1], hsv[:, :, 2]
    v_ch = _apply_clahe_gainmap(v_ch, 2.0)
    bgr = cv2.cvtColor(cv2.merge([h_ch, s_ch, v_ch]), cv2.COLOR_HSV2BGR)

    return bgr


# ── RAW10 → BGR ──────────────────────────────────────────────────────────────

def raw10_to_bgr_preview(lines: list, width: int, height: int) -> np.ndarray:
    """RAW10-Bayer-Zeilen → BGR Bild (einfache Pipeline)."""
    n_lines = min(len(lines), height)
    image = np.zeros((n_lines, width), dtype=np.uint16)

    for r in range(n_lines):
        raw = np.frombuffer(lines[r], dtype=np.uint8)
        n_groups = len(raw) // 5
        if n_groups == 0:
            continue
        raw = raw[:n_groups * 5].reshape(-1, 5)

        p1 = ((raw[:, 0].astype(np.uint16) << 2)
              | ((raw[:, 4].astype(np.uint16) >> 0) & 0x03))
        p2 = ((raw[:, 1].astype(np.uint16) << 2)
              | ((raw[:, 4].astype(np.uint16) >> 2) & 0x03))
        p3 = ((raw[:, 2].astype(np.uint16) << 2)
              | ((raw[:, 4].astype(np.uint16) >> 4) & 0x03))
        p4 = ((raw[:, 3].astype(np.uint16) << 2)
              | ((raw[:, 4].astype(np.uint16) >> 6) & 0x03))

        pixels = np.empty(n_groups * 4, dtype=np.uint16)
        pixels[0::4] = p1
        pixels[1::4] = p2
        pixels[2::4] = p3
        pixels[3::4] = p4

        valid = min(len(pixels), width)
        image[r, :valid] = pixels[:valid]

    img_8bit = (image >> 2).astype(np.uint8)

    try:
        return cv2.cvtColor(img_8bit, cv2.COLOR_BayerRG2BGR)
    except cv2.error:
        return cv2.cvtColor(img_8bit, cv2.COLOR_GRAY2BGR)


# ── RAW8 → BGR ───────────────────────────────────────────────────────────────

def raw8_to_bgr_preview(lines: list, width: int, height: int) -> np.ndarray:
    """RAW8-Bayer-Zeilen → BGR Bild (einfache Pipeline)."""
    n_lines = min(len(lines), height)
    image = np.zeros((n_lines, width), dtype=np.uint8)

    for r in range(n_lines):
        raw = np.frombuffer(lines[r], dtype=np.uint8)
        valid = min(len(raw), width)
        image[r, :valid] = raw[:valid]

    try:
        return cv2.cvtColor(image, cv2.COLOR_BayerRG2BGR)
    except cv2.error:
        return cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
