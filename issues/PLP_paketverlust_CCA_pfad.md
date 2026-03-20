# PLP Paketverlust auf CCA-Pfad (Stream 0x64 via CCA 9010)

> Erstellt: 2026-03-16
> Status: GELOEST
> Geloest: 2026-03-16

## Symptom

Live Capture zeigt auf dem Datenkanal 0x64 (via CCA 9010) sporadischen Paketverlust
(PLP Counter Gaps), waehrend derselbe Kamerastrom auf 0x67 (Direktverbindung) 0% Verlust hat.

**Das Video erscheint trotzdem komplett** — fehlende Zeilen werden durch den
persistenten Frame-Buffer mit Daten des vorherigen Frames aufgefuellt.

### Messwerte (2026-03-16, Laufzeit ~8h)

| Stream | Pfad | Interface | Counter Gaps | Verlorene Pakete | Verlustrate |
|--------|------|-----------|-------------|-----------------|-------------|
| 0x67 | Kamera → PC (direkt) | eno7np2 | 2 | 27.041 | 0.01% |
| 0x64 | Kamera → CCA 9010 → PC | eno8np3 | 884 | 57.153 | 0.01% |

Hinweis: Die Zuordnung Stream↔Interface ist **nicht fest** — kann bei Neustart wechseln.

## Ursache

### Root Cause: CCA 9010 veraendert Paket-Timing → NIC Adaptive Coalescing reagiert falsch

**Beweiskette:**

1. **Identische Hardware:** Beide Interfaces (eno7np2, eno8np3) sind Ports derselben
   i40e NIC (PCIe b7:00.2 / b7:00.3), gleiche Firmware 3.33, gleiche Konfiguration,
   gleicher NUMA-Node, gleicher CPU (CPU 7) fuer IRQ-Handling.

2. **Identischer Traffic:** Beide empfangen 48.385 pkt/s, 3.025 Mbit/s, avg 7.817 Bytes/Paket.

3. **Unterschiedliches Paket-Timing:**

| Metrik | Direkt (eno7np2) | Via CCA (eno8np3) |
|--------|-----------------|-------------------|
| Median-Intervall | 4.0 µs | 6.5 µs |
| StdDev (Jitter) | 104.9 µs | **253.1 µs (2.4×)** |
| Max-Intervall | 2.909 ms | **9.750 ms (3.4×)** |
| >5ms Pausen | 0 | 4 pro 5000 Pakete |
| Mikro-Bursts (<5µs) | 942 | 13 |
| Muster | Dicht gepackte Bursts | Gleichmaessig + lange Pausen |

4. **Adaptive Interrupt Coalescing Reaktion:**

| | Direkt (eno7np2) | Via CCA (eno8np3) |
|---|---|---|
| IRQ-Rate | 5.183/s | **870/s (6× weniger!)** |
| Pakete/IRQ | ~9 | **~56** |
| Ring-Buffer Fuellstand | ~9 Pakete | ~56 Pakete |

5. **Mechanismus:**
   - CCA pausiert Forwarding fuer ~10ms (internes Speichern/Verarbeiten)
   - Danach werden ~480 aufgestaute Pakete als Burst bei Leitungsgeschwindigkeit gesendet
   - NIC ist im "Spar-Modus" (870 IRQ/s) → draint Ring Buffer nur alle 1.15ms
   - Burst ueberlaeuft NIC-internen FIFO → `rx_missed_errors` steigt

### NIC Hardware Bestaetigung

```
eno7np2: rx_missed_errors=859   rx_crc_errors=413  (historisch, aktuell 0)
eno8np3: rx_missed_errors=65193 rx_crc_errors=0
```

`kern_drops=0` im AF_PACKET MMAP — Verlust geschieht VOR dem Kernel-Buffer.

### Warum Video trotzdem komplett

- 0.0066% Verlust ≈ 1 fehlende Zeile pro 4-5 Frames
- Persistent Frame Buffer fuellt Luecken mit vorherigem Frame
- Resize auf 960×540 maskiert Einzelzeilen-Artefakte

## Loesung

### Fix (UMGESETZT + VERIFIZIERT): Drei Massnahmen kombiniert

Einzeln reicht keine Massnahme — nur die Kombination erreicht Null-Verlust:

| Massnahme | Allein | Effekt |
|-----------|--------|--------|
| adaptive-rx off, rx-usecs=20 | 63 Drops/60s | 6× besser, aber nicht Null |
| adaptive-rx off, rx-usecs=10 | 192 Drops/60s | Verschlechtert! CPU-Overhead zu hoch |
| rx-usecs=20 + IRQ-Pinning | **0 Drops/180s** | **Loesung!** |

**Implementierung:** Skript `optimize_capture_nics.sh` erkennt automatisch alle
PROMISC-Interfaces (= Capture-NICs) und wendet drei Optimierungen an:

1. `adaptive-rx off, rx-usecs=20` — Feste Interrupt-Rate, kein Spar-Modus
2. `RX Ring = Hardware-Maximum` — Bereits 4096, nicht steigerbar
3. **IRQ-Pinning**: Jede NIC bekommt einen eigenen CPU-Kern (ab CPU 4, Abstand 2)
   → Vermeidet gegenseitige Blockierung bei gleichzeitigen Interrupts

**Warum Interface-unabhaengig:** Stream↔NIC Zuordnung ist nicht fest (0x64 kann
auf eno7np2 oder eno8np3 landen). Daher werden ALLE PROMISC-Interfaces optimiert.

**Persistenz:** Systemd Service `nic-capture-tuning.service` auf Remote-Maschine:
```
/etc/systemd/system/nic-capture-tuning.service  (enabled, nach network-online.target)
/usr/local/bin/optimize_capture_nics.sh          (Haupt-Skript)
```

**Verifizierung:** 3 Minuten Null-Verlust bei 48.385 pkt/s pro Interface (gesamt ~97k pkt/s).

### Fix RX Ring Buffer vergroessern

Nicht moeglich — i40e Hardware-Maximum ist 4096 (bereits gesetzt).

## Erkenntnisse

1. **Adaptive Interrupt Coalescing** kann bei gleichmaessigem Traffic die IRQ-Rate
   zu stark senken, wodurch kurze Bursts nicht abgefangen werden.
2. **Store-and-Forward Geraete** (CCA, Switches, Logger) veraendern das Paket-Timing
   fundamental — auch bei gleicher Datenrate.
3. **PLP Counter ist per-Probe global** — bei mehreren Streams auf einem Interface
   sind Per-Stream Counter-Luecken ERWARTET. Nur globale Luecken = echte Verluste.
4. **rx_missed_errors** (NIC-Level) vs **kern_drops** (AF_PACKET) unterscheiden:
   - rx_missed: Pakete nie in Host-RAM angekommen (NIC FIFO Overflow)
   - kern_drops: Pakete im RAM, aber AF_PACKET Ring voll (Software-Problem)
5. **tcpdump verursacht eigene Drops** bei hohem Durchsatz (350 MB/s Disk I/O) —
   nicht geeignet zum Messen von NIC-Level Verlusten.

## Service-Konsolidierung (2026-03-16)

### Vorher: 5 Services (互相冲突)

Ueber mehrere Sessions (Maerz 5–16) entstanden 5 einzelne systemd-Services,
die sich gegenseitig ueberschrieben haben:

```
eno8np3-nic.service        → 已删除 (nur Ring Buffer fuer eno8np3)
nic-ringbuffer.service     → 已删除 (nur Ring Buffer, redundant)
nic-irq-affinity.service   → 已删除 (绑错了队列! TxRx-2 statt TxRx-1)
nic-tuning.service         → 已删除 (rx-usecs=0 冲突 — siehe Details unten)
nic-capture-tuning.service → 保留，已更新为合并版
```

### Geloeschte Service-Inhalte (Archiv fuer Fehlersuche)

**eno8np3-nic.service** (2026-03-08):
```ini
[Service]
ExecStart=/usr/sbin/ethtool -G eno8np3 rx 4096
```
→ Nur eno8np3 Ring Buffer, hart-kodierter Interface-Name.

**nic-ringbuffer.service** (2026-03-05):
```ini
[Service]
ExecStart=/sbin/ethtool -G eno8np3 rx 4096 tx 4096
```
→ Gleiche Funktion wie oben, andere ethtool-Pfad.

**nic-irq-affinity.service** (2026-03-08):
```ini
[Service]
# eno7np2 TxRx-2 (IRQ 286) → CPU 8
ExecStart=/bin/bash -c "IRQ=$(grep eno7np2-TxRx-2 ...); echo 100 > /proc/irq/$IRQ/smp_affinity"
# eno8np3 TxRx-2 (IRQ 353) → CPU 10
ExecStart=/bin/bash -c "IRQ=$(grep eno8np3-TxRx-2 ...); echo 400 > /proc/irq/$IRQ/smp_affinity"
```
→ **Fehler:** Pinnt TxRx-2, aber der gesamte PLP-Traffic laeuft ueber TxRx-1!
  (Weil EtherType 0x2090 ohne IP-Header von RSS nicht verteilt wird.)

**nic-tuning.service** + **nic-tuning.sh** (2026-03-10):
```bash
# Kernfunktionen (jetzt in optimize_capture_nics.sh uebernommen):
# 1. Ring Buffer → Maximum
ethtool -G $iface rx $max_rx tx $max_tx

# 2. Coalescing — ACHTUNG: rx-usecs=0 war NICHT optimal!
#    Test zeigte: rx-usecs=0 und rx-usecs=10 → MEHR Drops wegen CPU-Overhead
ethtool -C $iface adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0

# 3. IRQ Affinity (alle Queues, nicht nur aktive)
for irq in $(grep "i40e-${iface}-TxRx" /proc/interrupts ...); do
    echo $cpu > /proc/irq/$irq/smp_affinity_list
done

# 4. RPS (Receive Packet Steering) — UEBERNOMMEN
echo $hex_mask > /sys/class/net/$iface/queues/rx-*/rps_cpus
echo 32768 > /sys/class/net/$iface/queues/rx-*/rps_flow_cnt

# 5. Kernel Tuning — UEBERNOMMEN
sysctl -w net.core.netdev_budget=4096
sysctl -w net.core.netdev_budget_usecs=16000
sysctl -w net.core.netdev_max_backlog=200000
echo 65536 > /proc/sys/net/core/rps_sock_flow_entries

# 6. Boot Race Condition: wartet bis zu 60s auf i40e Interfaces — UEBERNOMMEN
```

### Nachher: 1 Service (合并版)

```
nic-capture-tuning.service
  └── /usr/local/bin/optimize_capture_nics.sh
        ├── 自动检测 PROMISC/i40e 接口（不依赖固定名称）
        ├── 等待接口就绪（开机 Race Condition 防护，最长60秒）
        ├── Ring Buffer → 硬件最大值
        ├── adaptive-rx off + rx-usecs=20（实测最优值）
        │     rx-usecs=0  → CPU-Overhead zu hoch, MEHR Drops
        │     rx-usecs=10 → 192 Drops/60s (schlechter als default!)
        │     rx-usecs=20 → 63 Drops/60s (allein) → 0 Drops (mit IRQ-Pinning)
        │     rx-usecs=50 → Default, ~6.7 Drops/s auf CCA-Pfad
        ├── 活跃 RX 队列 IRQ 绑定独占 CPU（ab CPU4, Abstand 2）
        ├── RPS 多核分发（aus nic-tuning.sh uebernommen）
        └── Kernel netdev_budget/backlog 调优（aus nic-tuning.sh uebernommen）
```

### Revert-Befehl (falls Probleme auftreten)

```bash
sudo /usr/local/bin/optimize_capture_nics.sh revert
# Setzt zurueck: adaptive-rx on, rx-usecs=50, IRQ auf alle CPUs, RPS off
```

## Dateien/Tools

- Analyse-Skript: `/home/pengzhang/analyze_plp_loss.py` (lokale Kopie)
- NIC-Optimierung: `/usr/local/bin/optimize_capture_nics.sh` (Remote-Maschine)
- systemd Service: `/etc/systemd/system/nic-capture-tuning.service` (Remote)
- CaptureProcess Log: `/tmp/capture_process.log` (auf Remote-Maschine)
- Counter-Checker: `Messtechnik/core/counter_gap_checker.py`
- Live Capture: `Messtechnik/ui/wireshark_panel.py`
- CaptureWorker: `Messtechnik/core/capture_process.py`
