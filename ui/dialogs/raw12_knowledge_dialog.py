"""RAW12-Format Wissensbasis — Pixel, HDR Split-Pixel, RAW12 Packung, Stride."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QTextBrowser
)
from PyQt6.QtCore import Qt


# ── CSS ────────────────────────────────────────────────────────────────

_CSS = """<style>
body { font-family: 'Segoe UI', sans-serif; margin: 16px; color: #222; }
h1 { font-size: 20px; border-bottom: 2px solid #1976d2; padding-bottom: 6px; color: #1976d2; }
h2 { font-size: 15px; margin-top: 18px; color: #333; }
h3 { font-size: 13px; margin-top: 14px; color: #555; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th { background: #e3f2fd; text-align: left; padding: 6px 10px; border: 1px solid #ccc; }
td { padding: 6px 10px; border: 1px solid #ddd; vertical-align: top; }
tr:nth-child(even) { background: #fafafa; }
.info { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 8px 12px; margin: 12px 0; }
.warn { background: #fff3e0; border-left: 4px solid #ff9800; padding: 8px 12px; margin: 12px 0; }
code { background: #f0f0f0; padding: 1px 4px; font-family: 'Consolas', monospace; }
table.ftbl { border-collapse: collapse; width: 100%; margin: 10px 0; }
table.ftbl th { background: #e8eaf6; text-align: center; padding: 5px 8px;
                border: 1px solid #9e9e9e; font-size: 12px; color: #283593; }
table.ftbl td { text-align: center; padding: 5px 6px; border: 1px solid #bdbdbd;
                background: #fafafa; font-family: 'Consolas', monospace; font-size: 12px; }
table.ftbl td.hl-hcg { background: #ffebee; }
table.ftbl td.hl-lcg { background: #e8f5e9; }
table.ftbl td.hl-hdr { background: #e3f2fd; font-weight: bold; }
table.ftbl td.hl-head { background: #fff3e0; }
p { line-height: 1.6; }
ul { line-height: 1.8; }
</style>"""


# ── Seiten-Inhalte ────────────────────────────────────────────────────

_CONTENT: dict[str, str] = {}
_PAGE_ORDER: list[str] = []


def _page(title: str, html: str) -> str:
    return f"{_CSS}<h1>{title}</h1>{html}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1 — Was ist ein Pixel?
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('Pixel')
_CONTENT['Pixel'] = _page('Was ist ein Pixel?', """
<p>
<b>Pixel</b> (Picture Element) ist die kleinste Einheit eines digitalen Bildes.
Jedes Pixel speichert einen Helligkeits- oder Farbwert.
</p>

<h2>Kamera-Sensor vs. Display-Pixel</h2>
<table>
<tr><th>Eigenschaft</th><th>Sensor-Pixel (Aufnahme)</th><th>Display-Pixel (Anzeige)</th></tr>
<tr><td>Funktion</td><td>Wandelt Licht in elektrisches Signal um</td><td>Erzeugt sichtbares Licht</td></tr>
<tr><td>Farbinformation</td><td>Nur <b>eine</b> Farbe pro Pixel (durch Farbfilter)</td>
    <td><b>Drei</b> Sub-Pixel (R, G, B) pro Pixel</td></tr>
<tr><td>Typische Aufloesung</td><td>z.B. 3848 &times; 2168 (Sensor)</td>
    <td>z.B. 1920 &times; 1080 (Full HD)</td></tr>
</table>

<h2>Vom Sensor-Pixel zum Farbbild</h2>
<p>Ein Sensor-Pixel misst nur die <b>Intensitaet einer einzigen Farbe</b>,
bestimmt durch den Farbfilter darueber. Um ein Farbbild zu erzeugen,
braucht man eine <b>ISP-Pipeline</b> (Image Signal Processor):</p>
<table>
<tr><th>Schritt</th><th>Beschreibung</th></tr>
<tr><td>1. RAW-Daten</td><td>Jedes Pixel liefert einen 12-Bit Rohwert (0&ndash;4095)</td></tr>
<tr><td>2. Demosaicing</td><td>Aus dem Farbfilter-Muster (z.B. RCCB) werden fehlende
    Farbkanaele interpoliert</td></tr>
<tr><td>3. Farbkorrektur</td><td>Weissabgleich, Saettigung, Kontrastanpassung</td></tr>
<tr><td>4. Ausgabe</td><td>BGR-Bild mit 3 Kanaelen pro Pixel (8 Bit je Kanal)</td></tr>
</table>

<div class="info">
<b>Merke:</b> Ein Sensor-Pixel &ne; ein Display-Pixel. Der Sensor liefert Rohdaten,
die erst durch die ISP-Pipeline zu einem sichtbaren Farbbild werden.
</div>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2 — Split-Pixel HDR (HCG / LCG)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('Split-Pixel HDR')
_CONTENT['Split-Pixel HDR'] = _page('Split-Pixel HDR — HCG &amp; LCG', """
<p>
HDR-Bildsensoren (z.B. Sony IMX-Serie) verwenden den <b>Split-Pixel HDR</b>-Modus:
Jeder physische Sensor-Pixel wird in zwei Teile aufgeteilt, die gleichzeitig
mit unterschiedlicher Empfindlichkeit belichten.
</p>

<h2>HCG und LCG</h2>
<table>
<tr><th>Abkuerzung</th><th>Bedeutung</th><th>Empfindlichkeit</th><th>Erfasst</th></tr>
<tr><td><b>HCG</b></td><td>High Conversion Gain</td><td>Hoch (empfindlich)</td>
    <td>Dunkle Bereiche / Schatten</td></tr>
<tr><td><b>LCG</b></td><td>Low Conversion Gain</td><td>Niedrig (unempfindlich)</td>
    <td>Helle Bereiche / Highlights</td></tr>
</table>

<h2>Warum zwei Gain-Stufen?</h2>
<p>Ein einzelner Sensor kann nicht gleichzeitig sehr dunkle und sehr helle Bereiche
korrekt erfassen (begrenzter <b>Dynamikumfang</b>). Split-Pixel HDR loest das:</p>
<table>
<tr><th>Situation</th><th>HCG (hohe Empfindlichkeit)</th><th>LCG (niedrige Empfindlichkeit)</th></tr>
<tr><td>Dunkle Szene</td><td>Gutes Signal (brauchbar)</td><td>Zu dunkel (verrauscht)</td></tr>
<tr><td>Helle Szene</td><td>Ueberbelichtet (gesaettigt)</td><td>Gutes Signal (brauchbar)</td></tr>
<tr><td>HDR-Fusion</td><td colspan="2" style="text-align:center">
    Kombination beider &rarr; grosser Dynamikumfang</td></tr>
</table>

<h2>Physischer Sensor-Pixel vs. Daten-Pixel</h2>
<p>
Bei einer Kamera mit <b>3848 Spalten</b> im Sensor liefert Split-Pixel HDR:
</p>
<table>
<tr><th></th><th>Anzahl Spalten</th><th>Beschreibung</th></tr>
<tr><td>Physischer Sensor</td><td>3848</td><td>Alle Pixel (HCG + LCG gemischt)</td></tr>
<tr><td>HCG-Spalten</td><td>1924</td><td>Spalte 0, 2, 4, ... (gerade)</td></tr>
<tr><td>LCG-Spalten</td><td>1924</td><td>Spalte 1, 3, 5, ... (ungerade)</td></tr>
</table>

<h2>Pixel-Anordnung auf dem Sensor</h2>
<table class="ftbl">
<tr><th>Spalte 0</th><th>Spalte 1</th><th>Spalte 2</th><th>Spalte 3</th>
    <th>Spalte 4</th><th>Spalte 5</th><th>...</th><th>Spalte 3846</th><th>Spalte 3847</th></tr>
<tr><td class="hl-hcg">HCG</td><td class="hl-lcg">LCG</td>
    <td class="hl-hcg">HCG</td><td class="hl-lcg">LCG</td>
    <td class="hl-hcg">HCG</td><td class="hl-lcg">LCG</td>
    <td>...</td>
    <td class="hl-hcg">HCG</td><td class="hl-lcg">LCG</td></tr>
<tr><td class="hl-hcg">gerade</td><td class="hl-lcg">ungerade</td>
    <td class="hl-hcg">gerade</td><td class="hl-lcg">ungerade</td>
    <td class="hl-hcg">gerade</td><td class="hl-lcg">ungerade</td>
    <td>...</td>
    <td class="hl-hcg">gerade</td><td class="hl-lcg">ungerade</td></tr>
</table>

<div class="info">
<b>In unserem Code</b> wird nur LCG dekodiert (ausreichend fuer die Live-Vorschau).
Die resultierende Bildbreite ist daher <b>1924 Pixel</b> statt 3848.
</div>

<div class="warn">
<b>Wichtig:</b> HCG und LCG werden <b>nicht</b> getrennt uebertragen.
Beide sind in denselben Datenpaketen enthalten und werden beim Dekodieren
selektiv extrahiert &mdash; die jeweils andere Haelfte wird einfach ignoriert.
</div>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3 — RAW12 Packungsformat
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('RAW12 Packung')
_CONTENT['RAW12 Packung'] = _page('RAW12 Packungsformat', """
<p>
<b>RAW12</b> ist ein Packungsformat fuer 12-Bit Pixelwerte.
Da 12 Bit nicht in ein ganzes Byte passen, werden jeweils
<b>2 Pixel in 3 Bytes</b> gepackt (2 &times; 12 = 24 Bit = 3 Bytes).
</p>

<h2>Bit-Layout einer 3-Byte-Gruppe</h2>
<table class="ftbl">
<tr><th colspan="8">Byte 0 (8 Bit)</th>
    <th colspan="8">Byte 1 (8 Bit)</th>
    <th colspan="8">Byte 2 (8 Bit)</th></tr>
<tr><td class="hl-hcg" colspan="8">A[7:0]</td>
    <td class="hl-hcg" colspan="4">A[11:8]</td>
    <td class="hl-lcg" colspan="4">B[3:0]</td>
    <td class="hl-lcg" colspan="8">B[11:4]</td></tr>
<tr><td class="hl-hcg" colspan="12">Pixel A (HCG) &mdash; 12 Bit</td>
    <td class="hl-lcg" colspan="12">Pixel B (LCG) &mdash; 12 Bit</td></tr>
</table>

<h2>Dekodierungsformel</h2>
<table>
<tr><th>Pixel</th><th>Formel</th><th>Wertbereich</th><th>Gain-Typ</th></tr>
<tr><td>Pixel A</td>
    <td><code>(byte1 &amp; 0x0F) &lt;&lt; 8 | byte0</code></td>
    <td>0 &ndash; 4095</td>
    <td style="background:#ffebee">HCG (gerade Spalte)</td></tr>
<tr><td>Pixel B</td>
    <td><code>byte2 &lt;&lt; 4 | byte1 &gt;&gt; 4</code></td>
    <td>0 &ndash; 4095</td>
    <td style="background:#e8f5e9">LCG (ungerade Spalte)</td></tr>
</table>

<h2>Zahlenbeispiel</h2>
<table>
<tr><th>Byte</th><th>Hex</th><th>Binaer</th></tr>
<tr><td>byte0</td><td><code>0xAB</code></td><td><code>1010 1011</code></td></tr>
<tr><td>byte1</td><td><code>0x3C</code></td><td><code>0011 1100</code></td></tr>
<tr><td>byte2</td><td><code>0xDE</code></td><td><code>1101 1110</code></td></tr>
</table>
<p>Dekodierung:</p>
<table>
<tr><th>Pixel</th><th>Berechnung</th><th>Ergebnis</th></tr>
<tr><td>A (HCG)</td>
    <td><code>(0x3C &amp; 0x0F) &lt;&lt; 8 | 0xAB = 0xC &lt;&lt; 8 | 0xAB = 0xCAB</code></td>
    <td><b>3243</b></td></tr>
<tr><td>B (LCG)</td>
    <td><code>0xDE &lt;&lt; 4 | 0x3C &gt;&gt; 4 = 0xDE0 | 0x3 = 0xDE3</code></td>
    <td><b>3555</b></td></tr>
</table>

<div class="info">
<b>Im Code</b> wird nur Pixel B (LCG) extrahiert:<br>
<code>new_lcg = (byte2 &lt;&lt; 4) | (byte1 &gt;&gt; 4)</code><br>
Pixel A (HCG) wird uebersprungen &mdash; die 3 Bytes werden zwar gelesen,
aber nur die LCG-relevanten Bits verwendet.
</div>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4 — Stride und Zeilenlayout
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('Stride & Zeilenlayout')
_CONTENT['Stride & Zeilenlayout'] = _page('Stride und Zeilenlayout', """
<p>
<b>Stride</b> (Schrittweite) ist die Anzahl Bytes, die eine komplette Zeile
im Speicher belegt. Um von Zeile N zu Zeile N+1 zu springen,
bewegt man den Zeiger um genau <b>stride</b> Bytes vorwaerts.
</p>

<h2>Aufbau einer Zeile</h2>
<table class="ftbl">
<tr><th colspan="3">Eine Zeile = stride Bytes</th></tr>
<tr><td class="hl-lcg" style="width:80%">Pixel-Daten<br><small>stride &minus; 16 = 5772 Bytes</small></td>
    <td class="hl-head" style="width:20%">CSI-2 Header<br><small>16 Bytes</small></td>
    <td style="display:none"></td></tr>
</table>

<table>
<tr><th>Bestandteil</th><th>Groesse</th><th>Inhalt</th></tr>
<tr><td>Pixel-Daten</td><td>5772 Bytes</td>
    <td>1924 Gruppen &times; 3 Bytes = 3848 Pixel (RAW12-gepackt)</td></tr>
<tr><td>CSI-2 Header</td><td>16 Bytes</td>
    <td>Protokoll-Overhead (Data-Type, Word-Count, Zeilennummer etc.)</td></tr>
<tr><td><b>Stride (gesamt)</b></td><td><b>5788 Bytes</b></td>
    <td>5772 + 16</td></tr>
</table>

<h2>Zeilenadressierung im Speicher</h2>
<table>
<tr><th>Zeile</th><th>Startadresse</th><th>Berechnung</th></tr>
<tr><td>Zeile 0</td><td>0</td><td>0 &times; 5788</td></tr>
<tr><td>Zeile 1</td><td>5788</td><td>1 &times; 5788</td></tr>
<tr><td>Zeile 2</td><td>11576</td><td>2 &times; 5788</td></tr>
<tr><td>Zeile N</td><td>N &times; 5788</td><td>N &times; stride</td></tr>
<tr><td>Zeile 2167 (letzte)</td><td>12&thinsp;551&thinsp;396</td><td>2167 &times; 5788</td></tr>
</table>

<h2>Pixel-Daten im Detail (eine Zeile)</h2>
<table class="ftbl">
<tr><th>Byte-Offset</th><th>0&ndash;2</th><th>3&ndash;5</th><th>6&ndash;8</th>
    <th>...</th><th>5769&ndash;5771</th><th>5772&ndash;5787</th></tr>
<tr><th>Inhalt</th>
    <td>Gruppe 0<br><small>3 Bytes</small></td>
    <td>Gruppe 1<br><small>3 Bytes</small></td>
    <td>Gruppe 2<br><small>3 Bytes</small></td>
    <td>...</td>
    <td>Gruppe 1923<br><small>3 Bytes</small></td>
    <td class="hl-head">CSI-2 Hdr<br><small>16 Bytes</small></td></tr>
<tr><th>Pixel</th>
    <td><span style="color:#c62828">HCG<sub>0</sub></span> +
        <span style="color:#2e7d32">LCG<sub>0</sub></span></td>
    <td><span style="color:#c62828">HCG<sub>1</sub></span> +
        <span style="color:#2e7d32">LCG<sub>1</sub></span></td>
    <td><span style="color:#c62828">HCG<sub>2</sub></span> +
        <span style="color:#2e7d32">LCG<sub>2</sub></span></td>
    <td>...</td>
    <td><span style="color:#c62828">HCG<sub>1923</sub></span> +
        <span style="color:#2e7d32">LCG<sub>1923</sub></span></td>
    <td class="hl-head">&mdash;</td></tr>
</table>

<div class="info">
<b>Zusammenfassung der Groessen:</b><br>
1924 Gruppen &times; 3 Bytes = <b>5772 Bytes</b> Pixel-Daten<br>
5772 + 16 = <b>5788 Bytes</b> Stride<br>
2168 Zeilen &times; 5788 = <b>~12.5 MB</b> pro Frame<br>
Bei 30 fps: ~<b>375 MB/s</b> Rohdatenrate
</div>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5 — Gesamtueberblick: Vom Sensor zum Bild
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('Sensor zum Bild')
_CONTENT['Sensor zum Bild'] = _page('Gesamtueberblick: Vom Sensor zum Bild', """
<p>Der komplette Datenpfad von der Kamera bis zum angezeigten Bild:</p>

<table>
<tr><th>Stufe</th><th>Beschreibung</th><th>Datenformat</th></tr>
<tr><td>1. Sensor</td>
    <td>3848 &times; 2168 Pixel, Split-Pixel HDR (HCG+LCG abwechselnd)</td>
    <td>Analoge Signale</td></tr>
<tr><td>2. ADC</td>
    <td>Analog-Digital-Wandlung, 12 Bit pro Pixel</td>
    <td>12-Bit Rohwerte</td></tr>
<tr><td>3. RAW12 Packung</td>
    <td>Je 2 Pixel in 3 Bytes gepackt, CSI-2 Header angehaengt</td>
    <td>5788 Bytes/Zeile</td></tr>
<tr><td>4. MIPI CSI-2</td>
    <td>Uebertragung ueber GMSL-Serializer an den Empfaenger</td>
    <td>CSI-2 Pakete</td></tr>
<tr><td>5. Netzwerk</td>
    <td>Ethernet-Kapselung (PLP/TECMP), ~750 MB/s Datenrate</td>
    <td>UDP-Pakete</td></tr>
<tr><td>6. Empfang</td>
    <td>Socket-Capture, Reassembly zu Zeilen</td>
    <td>Rohe Zeilen + Timestamps</td></tr>
<tr><td>7. LCG-Extraktion</td>
    <td>Nur LCG-Pixel dekodieren (ungerade Spalten)</td>
    <td>1924 &times; 2168, uint16</td></tr>
<tr><td>8. ISP-Pipeline</td>
    <td>Binning, Demosaic (RCCB), Farbkorrektur, Resize</td>
    <td>960 &times; 540, BGR uint8</td></tr>
<tr><td>9. Anzeige</td>
    <td>Qt QLabel mit QPixmap</td>
    <td>RGB-Bild auf dem Display</td></tr>
</table>

<div class="warn">
<b>Engpass:</b> Bei Schritt 5&rarr;6 koennen durch die hohe Datenrate (~750 MB/s)
Pakete verloren gehen (Kernel-Drop). Dies fuehrt zu fehlenden Zeilen im Bild
und ist die Hauptursache fuer Bildstoerrungen bei der Live-Vorschau.
</div>
""")


# ── Dialog-Klasse ─────────────────────────────────────────────────────

class Raw12KnowledgeDialog(QDialog):
    """Wissensbasis-Dialog fuer RAW12-Format und Sensor-Grundlagen."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Wissen — RAW12-Format & Sensor-Grundlagen')
        self.resize(1000, 700)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMinimumWidth(180)
        self._tree.setMaximumWidth(260)
        splitter.addWidget(self._tree)

        self._browser = QTextBrowser()
        self._browser.setOpenExternalLinks(True)
        splitter.addWidget(self._browser)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([220, 780])
        layout.addWidget(splitter)

        # Baum befuellen
        self._items: dict[str, QTreeWidgetItem] = {}
        for name in _PAGE_ORDER:
            item = QTreeWidgetItem([name])
            self._tree.addTopLevelItem(item)
            self._items[name] = item

        self._tree.currentItemChanged.connect(self._on_item_changed)

        if _PAGE_ORDER:
            self._tree.setCurrentItem(self._items[_PAGE_ORDER[0]])

    def _on_item_changed(self, current, _previous):
        if current is None:
            return
        name = current.text(0)
        html = _CONTENT.get(name, '')
        self._browser.setHtml(html)
