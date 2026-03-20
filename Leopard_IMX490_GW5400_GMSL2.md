# Leopard Imaging LI-IMX490-GW5400-GMSL2-030H — Technische Referenz

> Kamera: LI-IMX490-GW5400-GMSL2-030H (JQ6P0190)
> Capture-Modul: Technica Engineering CM SerDes GMSL2/3 (TE-1190)
> Erstellt: 2026-03-10

---

## 1. Kamera-Spezifikationen

| Eigenschaft | Wert |
|---|---|
| Sensor | Sony IMX490, 5.36 MP CMOS, 1/1.55" |
| ISP | GEO Semiconductor GW5400 (HDR, LFM) |
| Serializer | **MAX96717** (Device ID: **0xBF**, Rev: 0x06) |
| Auflösung | 2880 (H) x 1860 (V) |
| Frame Rate | 25 fps @ 2880x1860 |
| Ausgabeformat | **YUV422 8-bit** (vom GW5400 ISP verarbeitet) |
| CSI-2 Data Type | **0x1E** (YUV422 8-bit) |
| Stecker | FAKRA Z Type |
| Kabel | FAK-SMZSMZ-3M (3 Meter) |
| Stromversorgung | 9–19 VDC, 176 mA @ 12V (PoC) |
| Gemessener Strom | 195 mA über PoC |
| IP-Schutzklasse | IP67 / IP69K |
| Betriebstemperatur | -40°C bis +85°C |

**WICHTIG:** Das Datenblatt von Leopard nennt MAX9295A/B als Serializer, aber
die tatsächliche Hardware (JQ6P0190) verwendet **MAX96717** (Device ID 0xBF bei Register 0x000D).

---

## 2. CM SerDes Konfiguration (TE-1190)

### Hardware
| CM SerDes Komponente | Chip |
|---|---|
| Serializer (ECU-Seite) | Analog Devices MAX96793 |
| Deserializer (Sensor-Seite) | Analog Devices MAX96792A |

### Verkabelung
```
Kamera (MAX96717) ──FAKRA Koax──► CM SerDes Deser-Port (MAX96792A)
                                        │
                                   Tap/Capture
                                        │
                                  SFP+ 10G ──► Data Logger (PCAP)
                                  RJ-45 1G ──► Config-PC (Web UI: 10.104.3.192)
```

- **Kamera MUSS an Deser-Port** (nicht Ser-Port!)
- **PoC aktivieren** — Kamera wird über Koax mit 12V versorgt
- Konfigurationsname: `VIGEM_Leopard`

### Web-Interface Einstellungen (LINK-1)

#### GMSL-Tab
| Parameter | Wert |
|---|---|
| GMSL Speed | **GMSL2 6Gbps** |
| Video Transmission Mode | **Tunnel mode** |
| GMSL Video Stream ID | 0 |
| Serializer I2C address | 0x80 (8-bit) = 0x40 (7-bit) |
| Deserializer I2C address | 0xD4 (8-bit) = 0x6A (7-bit) |

#### VIDEO 0-Tab
| Parameter | Wert |
|---|---|
| Virtual Channel | **0** |
| Bus ID (hex) | 68 |
| MIPI Datatype Overwrite | **Enabled** |
| Forced MIPI Datatype | **0x1E - YUV 8bit** |
| Apply to | All MIPI video packets |

#### LOGGING-Tab
| Parameter | Wert |
|---|---|
| Output to | SFP+ A |
| Payload Size | 6000 bytes |
| Pixel Arrangement | 0-padded byte-aligned |
| FPGA Video Path 0 | Enabled |
| Compression | Aus (optional aktivierbar) |

#### POC-Tab
| Parameter | Wert |
|---|---|
| PoC Injection | **Enabled (12V)** |
| Injected Current | ~195 mA |
| Alle Schutzmechanismen | OK |

---

## 3. MAX96717 Serializer — Register-Referenz

### Identifikation
| Register | Adresse | Gelesener Wert | Bedeutung |
|---|---|---|---|
| DEV_ID | 0x000D | **0xBF** | MAX96717 |
| DEV_REV | 0x000E | **0x06** | Revision 6 |
| REG2 | 0x0002 | **0x43** | Status |
| REG6 | 0x0006 | **0xB0** | Config (RCLKEN=1) |

### Wichtige Register (aus Linux-Kernel-Treiber)
| Register | Adresse | Bits | Funktion |
|---|---|---|---|
| VIDEO_TX2 | **0x0112** | bit 7 = PCLKDET | Pixel-Clock-Erkennung |
| MIPI_RX1 | **0x0331** | bits 5:4 | CSI-2 Lane-Anzahl |
| MIPI_RX2 | 0x0332 | bits 7:4 | PHY2 Lane Mapping |
| MIPI_RX3 | 0x0333 | bits 3:0 | PHY1 Lane Mapping |
| MIPI_RX4 | 0x0334 | bits 6:4 | PHY1 Lane Polarity |
| MIPI_RX5 | 0x0335 | bits 2:0 | PHY2 Lane Polarity |
| MIPI_RX_EXT11 | **0x0383** | bit 7 = TUN_MODE | Tunnel-Modus |
| FRONTOP0 | **0x0308** | bit 5 = START_PORT_B | CSI-Übertragung starten |
| REF_VTG0 | 0x03F0 | diverse | PLL / Referenz-Clock |
| GPIO_REG_A(n) | 0x2BE+n*3 | diverse | GPIO-Konfiguration |
| PIO_SLEW_1 | 0x0570 | — | Slew Rate |

### I2C-Adressübersetzung
| Register | Adresse | Gelesener Wert | Status |
|---|---|---|---|
| SRC_A | 0x0042 | 0x00 | Nicht konfiguriert |
| DST_A | 0x0043 | 0x00 | Nicht konfiguriert |
| SRC_B | 0x0044 | 0x00 | Nicht konfiguriert |
| DST_B | 0x0045 | 0x00 | Nicht konfiguriert |

**Alle I2C-Übersetzungsregister sind leer → GW5400 ISP ist über I2C nicht erreichbar.**

---

## 4. Advanced Diagnostics — Ergebnisse (Link 1)

| Komponente | Test | Ergebnis | Bedeutung |
|---|---|---|---|
| Deserializer | LOCKED_A | **OK** | GMSL2-Link aufgebaut |
| Serializer | LOCKED | **NOK** | Kein CSI-2-Eingang erkannt |
| Serializer | PCLKDET | **NOK** | Kein Pixel-Clock erkannt |
| Deserializer | VID_PKT_DET_1 | **NOK** | Keine Video-Pakete |
| Deserializer | VID_OVERFLOW_1 | OK | Kein Überlauf |
| Serializer | OVERFLOW_R | OK | Kein Überlauf |
| Serializer | ERRB | OK | Kein Fehler |
| Deserializer | ERRB | OK | Kein Fehler |

**Kernproblem:** GMSL2-Link steht, aber GW5400 ISP sendet kein CSI-2-Video.
Der MAX96717 erkennt weder Pixel-Clock noch Daten am CSI-2-Eingang.

---

## 5. GW5400 ISP — I2C-Zugang

### I2C-Bus-Scan Ergebnisse (2026-03-10)
| I2C-Adresse (8-bit) | 7-bit | Ergebnis | Gerät |
|---|---|---|---|
| **0x80** | 0x40 | OK | MAX96717 Serializer |
| **0xDA** | 0x6D | **OK (0x00)** | **GW5400 ISP — ERREICHBAR!** |
| **0xD4** | 0x6A | OK (0xD4) | MAX96792A Deserializer (CM SerDes intern) |
| 0xD8 | 0x6C | Transfer Error | Kein Gerät |
| 0x20 | 0x10 | Transfer Error | Kein Gerät (IMX490 nicht direkt erreichbar) |
| 0x34 | 0x1A | Transfer Error | Kein Gerät |

### Status
- **GW5400 ISP ist über GMSL2-Link ERREICHBAR bei I2C-Adresse 0xDA**
- MAX96717 leitet I2C automatisch an die lokale Kamera-Bus weiter
- GW5400 ist eingeschaltet und I2C-kommunikationsfähig
- **ABER: GW5400 streamt KEIN Video (PCLKDET=NOK) — benötigt "Stream ON" Befehl**
- **Leopard Imaging muss die I2C-Stream-ON-Sequenz liefern**
  (Kontakt: support@leopardimaging.com)

### MAX96717 CSI-2 Konfiguration (verifiziert)
| Register | Adresse | Wert | Bedeutung |
|---|---|---|---|
| VIDEO_TX2 | 0x0112 | 0x0A | PCLKDET=0 (kein Pixel-Clock) |
| MIPI_RX1 | 0x0331 | 0x30 | 4 CSI-2 Lanes konfiguriert ✓ |
| MIPI_RX_EXT11 | 0x0383 | 0x80 | Tunnel-Modus aktiv ✓ |
| FRONTOP0 | 0x0308 | 0x64 | START_PORT aktiv ✓ |

---

## 6. Datenverarbeitung in der Messtechnik-Software

### Unterschied zu bisherigen GMSL-Streams
| Eigenschaft | Bisherige Kameras (0x2090) | Leopard IMX490/GW5400 |
|---|---|---|
| CSI-2 Data Type | 0x2C (RAW12) | **0x1E (YUV422 8-bit)** |
| Sensor-Layout | RCCB Dual-Gain | Standard Bayer (im ISP) |
| ISP nötig? | Ja (Demosaic + ISP Pipeline) | **Nein** (GW5400 hat verarbeitet) |
| Farbkonvertierung | RAW12 → Demosaic → ISP → BGR | **YUV422 → BGR** (einfach) |
| Stride-Berechnung | 2 Pixel = 3 Bytes (RAW12) | 2 Pixel = 4 Bytes (YUV422) |

### YUV422 Dekodierung (für converter_panel.py / bildvorschau_dialog.py)
```python
import cv2
import numpy as np

# YUV422 (UYVY) Frame dekodieren
width, height = 2880, 1860
yuv_data = np.frombuffer(raw_bytes, dtype=np.uint8).reshape(height, width, 2)
bgr_frame = cv2.cvtColor(yuv_data, cv2.COLOR_YUV2BGR_UYVY)

# Alternativ: YUV422 (YUYV)
bgr_frame = cv2.cvtColor(yuv_data, cv2.COLOR_YUV2BGR_YUY2)
```

### Bandbreiten-Berechnung
- 2880 × 1860 × 2 Bytes (YUV422) × 25 fps = **~256 MB/s = ~2.14 Gbps**
- GMSL2 6Gbps: ausreichend
- 10G SFP+: ausreichend

---

## 7. Offene Punkte / TODO

- [x] Kamera an Deser-Port anschließen (nicht Ser-Port)
- [x] PoC aktivieren — 195 mA bestätigt
- [x] GMSL2-Link aufgebaut (LOCKED_A = OK)
- [x] MAX96717 identifiziert (DEV_ID=0xBF, nicht MAX9295A/B)
- [x] MAX96717 CSI-2 Konfiguration verifiziert (4 Lanes, Tunnel, START_PORT)
- [x] GW5400 ISP gefunden bei I2C 0xDA
- [ ] **Leopard Imaging kontaktieren: "Stream ON" Befehl für GW5400 ISP anfordern**
- [ ] GW5400 ISP starten (Streaming aktivieren)
- [ ] Nach erfolgreichem Streaming: PCLKDET und VID_PKT_DET_1 erneut prüfen
- [ ] YUV422-Dekodierung in converter_panel.py / bildvorschau_dialog.py implementieren
- [ ] Testen ob UYVY oder YUYV Byte-Order

---

## 8. Quellen

- [CM SerDes GMSL2/3 Datasheet (TE-1190)](https://www.technica-engineering.com/wp-content/uploads/2025/07/TE-1190_CM_SerDes_datasheet_v1_1.pdf)
- [LI-IMX490-GW5400-GMSL2-xxxH Datasheet](https://leopardimaging.com/wp-content/uploads/pdf/LI-IMX490-GW5400-GMSL2-xxxH_Datasheet_V1.2.pdf)
- [MAX96717 Datasheet (Analog Devices)](https://www.analog.com/media/en/technical-documentation/data-sheets/max96717.pdf)
- [MAX96717/F/R User Guide](https://www.analog.com/media/en/technical-documentation/user-guides/max96717fr-user-guide.pdf)
- [MAX96717 Linux Kernel Driver](https://github.com/torvalds/linux/blob/master/drivers/media/i2c/max96717.c)
- [GMSL2 General User Guide](https://www.analog.com/media/en/technical-documentation/user-guides/gmsl2-general-user-guide.pdf)
