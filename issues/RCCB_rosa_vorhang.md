# RCCB Farbproblem: Vorhang erscheint rosa statt beige

> Erstellt: 2026-03-13
> Status: OFFEN — Debugging bei Tageslicht geplant

---

## Symptom

- Vorhang im Bild erscheint **rosa/pink**, reale Farbe ist **beige/cremig**
- R-Faktor senken reduziert zwar Rosa, aber das **gesamte Bild wird gruenlich**
- Lokale Farbkorrektur (nur Vorhang) ist mit R/B-Faktor nicht moeglich

## Ursache

Der Sensor ist **RCCB** (Red-Clear-Clear-Blue), kein Standard-RGGB.

### Aktueller ISP-Pipeline-Ablauf (`capture_process.py:1154`)

1. Bayer 2x2 Binning
2. Black-Level + White-Point → uint8 LUT
3. **Bayer RG Demosaic** (`cv2.COLOR_BayerRG2BGR`) ← Problem hier
4. White Balance (Gray World) + Gamma
5. Resize

### Root Cause: Clear-Kanal Crosstalk

- `cv2.COLOR_BayerRG2BGR` behandelt die **Clear-Pixel als Gruen**
- Clear-Pixel reagieren auf **alle Wellenlaengen** (inkl. Rot)
- → Der "Gruen"-Kanal enthaelt Rot-Informationen (Crosstalk)
- Gray-World White Balance (`gain_r = gm/rm`) korrigiert **global**, kann den Crosstalk nicht kompensieren
- Warme Farben (beige/creme) werden durch den Clear→Gruen Crosstalk zu Rosa verschoben

### Warum R/B-Faktor nicht hilft

- R-Faktor ist eine **globale** lineare Skalierung des R-Kanals (`_apply_rb_correction`)
- Senkt man R, wird der Vorhang weniger rosa, aber alles andere wird gruenlich
- Das Problem liegt nicht im R-Kanal allein, sondern im **Crosstalk zwischen Clear und R**

---

## Loesungsvorschlaege

### Loesung 1: Color Correction Matrix (CCM) — EMPFOHLEN

3x3-Matrix nach Demosaic, vor White Balance. Mappt RCCB-Farbraum → sRGB.

```python
# In _isp_pipeline(), nach Demosaic (Schritt 3), vor White Balance (Schritt 4):
ccm = np.array([[ 1.5, -0.3, -0.2],
                [-0.2,  1.3, -0.1],
                [-0.1, -0.2,  1.3]], dtype=np.float32)
bgr_f = bgr_8.astype(np.float32)
bgr_8 = np.clip(bgr_f @ ccm.T, 0, 255).astype(np.uint8)
```

- **Vorteile:** Industriestandard, korrigiert mehrere Farbfehler gleichzeitig
- **Nachteile:** Matrix-Koeffizienten muessen fuer diesen Sensor kalibriert werden
- **UI:** Evtl. ein paar Schieberegler fuer Feinabstimmung (Diagonalwerte)

### Loesung 2: HSV selektive Entsaettigung (Rosa/Magenta)

Nur den rosa/magenta Farbbereich im HSV-Raum entsaettigen:

```python
# Nach White Balance:
hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
# Rosa/Magenta: H ca. 140-180 oder 0-10
mask = (hsv[:,:,0] > 140) | (hsv[:,:,0] < 10)
hsv[:,:,1][mask] = (hsv[:,:,1][mask] * 0.5).astype(np.uint8)
bgr = cv2.cvtColor(hsv, cv2.COLOR_HSV2BGR)
```

- **Vorteile:** Schnell sichtbar, beeinflusst nur Rosatoene
- **Nachteile:** Symptombehandlung, behebt nicht die Grundursache

### Loesung 3: Clear-Kanal Crosstalk-Kompensation

Vom Gruen-Kanal anteilig (R+B)/2 abziehen:

```python
# Nach Demosaic:
g = bgr_8[:,:,1].astype(np.float32)
r = bgr_8[:,:,2].astype(np.float32)
b = bgr_8[:,:,0].astype(np.float32)
alpha = 0.15  # Crosstalk-Koeffizient (muss kalibriert werden)
g_corrected = np.clip(g - alpha * (r + b) / 2, 0, 255)
bgr_8[:,:,1] = g_corrected.astype(np.uint8)
```

- **Vorteile:** Adressiert direkt die Ursache
- **Nachteile:** Kann Gesamthelligkeit beeinflussen

---

## Relevante Code-Stellen

| Datei | Zeile | Beschreibung |
|-------|-------|-------------|
| `core/capture_process.py` | 1154 | `_isp_pipeline()` — Haupt-ISP |
| `core/capture_process.py` | 1205 | Demosaic: `COLOR_BayerRG2BGR` |
| `core/capture_process.py` | 1208-1236 | White Balance + Gamma |
| `ui/wireshark_panel.py` | 4507 | `_apply_rb_correction()` — R/B-Faktor |

## Naechste Schritte

1. Bei Tageslicht testen (natuerliche Beleuchtung fuer zuverlaessige Farbbeurteilung)
2. ISP-Log pruefen: `cat /tmp/0x2090_isp.log` (pre/post WB R/G/B Werte)
3. Loesung 1 (CCM) implementieren und Koeffizienten kalibrieren
