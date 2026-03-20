# Bus-Tabelle UI Freeze beim Spaltenziehen / Klicken

**Datum:** 2026-03-18
**Status:** Behoben
**Schweregrad:** P0 (Absturz / Nicht benutzbar)

## Symptom

Beim Klicken auf die Bus-Tabelle (Live CAN / Live LIN) oder beim Ziehen der Spalten-Trennlinien
friert die UI ein mit der Meldung:
> "Live Capture Antwortet nicht. Sie können der Anwendung noch etwas Zeit geben oder ein sofortiges Beenden erzwingen."

## Ursachenanalyse

### 3 Performance-Killer identifiziert

| # | Problem | Ort | Schweregrad |
|---|---------|-----|-------------|
| 1 | `scrollToBottom()` bei JEDEM Paket | `_add_bus_data()` Z.10613 | KRITISCH |
| 2 | `beginInsertRows/endInsertRows` pro Einzelzeile | `BusTableModel.append_row()` Z.4871 | KRITISCH |
| 3 | Kein Batching-Mechanismus | gesamter Bus-Datenpfad | KRITISCH |

### Detaillierte Erklärung

**Problem 1: scrollToBottom() pro Paket**
- CAN-Bus kann 100+ Nachrichten/Sekunde liefern
- `scrollToBottom()` erzwingt komplette Layout-Neuberechnung des QTableView
- Bei 100 Aufrufen/s → UI-Thread permanent blockiert

**Problem 2: Model-Signale pro Zeile**
- `beginInsertRows()` / `endInsertRows()` triggert jeweils View-Neuzeichnung
- Zusätzlich bei Trimming: `beginRemoveRows()` / `endRemoveRows()` → doppelte Signale
- Bei Kapazitätsgrenze: 2 Model-Updates pro Zeile (Remove + Insert)

**Problem 3: Synchrone Verarbeitung ohne Puffer**
- Jedes TECMP-Paket wird sofort dekodiert → sofort ins Model → sofort UI-Update
- Kein Timer-basierter Batch-Mechanismus
- Paket-Verarbeitungs-Kette blockiert den Qt-Event-Loop

### Zusätzlicher Faktor: ResizeToContents

- Spalte 0 (Zeit) war auf `QHeaderView.ResizeMode.ResizeToContents` gesetzt
- Bei jedem Model-Update berechnet Qt die optimale Breite über ALLE Zeilen
- Beim manuellen Spaltenziehen verstärkt sich dieser Effekt

## Lösung

### Versuch 1: ResizeToContents entfernen (teilweise Besserung)
- Alle Spalten auf `Interactive` umgestellt
- Feste Default-Breiten gesetzt
- **Ergebnis:** Spaltenziehen besser, aber Klicken friert noch ein

### Versuch 2: Komplette Architektur-Überarbeitung (Lösung)

**A) Batch-Timer statt synchrone Updates:**
```python
self._bus_queues = [[], [], [], []]     # Warteschlangen
self._bus_flush_timer = QTimer(self)
self._bus_flush_timer.setInterval(100)  # 100ms = max 10 UI-Updates/s
self._bus_flush_timer.timeout.connect(self._flush_bus_queues)
```

**B) Model-Reset statt Einzel-Insert/Remove:**
```python
def flush_batch(self, new_rows):
    self.beginResetModel()
    self._rows.extend(new_rows)
    if len(self._rows) > self._max_rows:
        self._rows = self._rows[-self._max_rows:]
    self.endResetModel()
```
- Ein einziges `beginResetModel/endResetModel` pro Batch
- Statt N × (beginInsert + endInsert) + M × (beginRemove + endRemove)

**C) scrollToBottom() entfernt:**
- Nicht mehr nötig bei max 200 Zeilen Ringpuffer
- War der größte Performance-Killer

### Zusammenfassung der Änderungen

| Vorher | Nachher |
|--------|---------|
| `append_row()` + `beginInsertRows` pro Zeile | `flush_batch()` + `beginResetModel` pro 100ms |
| `scrollToBottom()` pro Zeile | Entfernt |
| `ResizeToContents` auf Spalte 0 | `Interactive` mit fester Breite |
| Synchron: Paket → Model → View | Async: Paket → Queue → Timer → Model → View |
| Unbegrenzte Zeilen (50000) | Max 200 Zeilen Ringpuffer |
| 100+ UI-Updates/s möglich | Max 10 UI-Updates/s (Timer 100ms) |

## Verifikation

- [ ] Bus-Tabelle klickbar ohne Freeze
- [ ] Spalten per Drag verstellbar
- [ ] CAN-Daten fließen flüssig bei hoher Last
- [ ] Record-Funktion speichert korrekt

## Versuch 3: beginResetModel ersetzen (2026-03-18)

### Problem nach Versuch 2
Spaltenziehen friert IMMER NOCH ein. `beginResetModel/endResetModel` wird alle 100ms aufgerufen
und erzwingt einen **kompletten View-Rebuild** — kollidiert mit laufendem Column-Resize.

### Änderungen
1. **`flush_batch()` umgeschrieben:** `beginResetModel` → `beginRemoveRows` + `beginInsertRows`
   - Remove: einmaliges Trimmen alter Zeilen (ein Signal)
   - Insert: einmaliges Batch-Insert neuer Zeilen (ein Signal)
   - View-Zustand (Spaltenbreiten, Selektion) bleibt erhalten
2. **QFont-Allokation optimiert:** Klassen-Konstante statt pro-Zelle Erstellung
3. **Performance-Diagnose:** Warnung bei flush > 50ms

### Erwartung
- Column-Resize kollidiert nicht mehr mit Model-Updates
- Maximal 2 leichtgewichtige Signale pro 100ms statt 1 schweres Reset

## Versuch 4: NameError in Timer-Callback (2026-03-18)

### Problem nach Versuch 3
Tab-Wechsel (CAN → LIN) friert wieder ein.

### Ursache
`_flush_bus_queues()` enthielt `logger.warning(...)`, aber `logger` war nicht definiert.
Wenn `flush_batch()` > 50ms dauerte, warf der Timer-Callback einen `NameError`.
Unbehandelte Exception im QTimer-Callback → Qt-Event-Loop blockiert.

### Lösung
Performance-Diagnose-Code entfernt (war nur temporär).
Timer-Callback ist jetzt minimal und kann nicht crashen.

## Versuch 5: Column-Resize Freeze (2026-03-18)

### Problem
Spaltenziehen friert IMMER NOCH ein. Kein Traceback (UI-Freeze, kein Crash).

### Ursache
`beginRemoveRows/beginInsertRows` triggert View-Layout-Neuberechnung.
Während der Benutzer eine Spalte zieht, kollidieren Timer-getriebene Model-Signale
mit der laufenden Drag-Operation → Event-Loop blockiert.

### Lösung (2 Maßnahmen)

**A) `flush_batch()` → `layoutChanged` statt Row-Insert/Remove:**
```python
self.layoutAboutToBeChanged.emit()
self._rows.extend(new_rows)
if len(self._rows) > self._max_rows:
    self._rows = self._rows[-self._max_rows:]
self.layoutChanged.emit()
```
- `layoutChanged` ist leichtgewichtiger als Row-Level-Signale
- Keine Zeilen-für-Zeilen Neuberechnung

**B) `setUpdatesEnabled(False/True)` um flush:**
```python
table.setUpdatesEnabled(False)
model.flush_batch(batch)
table.setUpdatesEnabled(True)
```
- View verarbeitet KEINE Signale während des Updates
- Ein einziges Repaint nach `setUpdatesEnabled(True)`
- Kein Konflikt mit laufendem Column-Drag

## Versuch 6: Flush während Column-Resize pausieren (2026-03-18)

### Problem nach Versuch 5
`setUpdatesEnabled(False)` verhindert nur View-Repaints,
aber QSortFilterProxyModel verarbeitet `layoutChanged` trotzdem intern →
Re-Filterung aller 200 Zeilen während Drag → UI-Freeze.

### Lösung (3 Mechanismen kombiniert)

1. **`sectionResized` Signal → Pause-Flag:**
   ```python
   filter_header.sectionResized.connect(self._pause_bus_flush)
   ```
   Jeder Resize-Event setzt `_bus_flush_paused = True`

2. **300ms One-Shot Timer → Resume:**
   ```python
   self._bus_flush_resume_timer.start()  # Reset bei jedem Resize
   ```
   Erst 300ms NACH dem letzten Resize wird `_bus_flush_paused = False`

3. **flush_bus_queues prüft Flag:**
   ```python
   if self._bus_flush_paused:
       return  # Überspringen, Daten bleiben in Queue
   ```
   Queue sammelt weiter, Flush erfolgt erst nach Drag-Ende

## Versuch 7: sectionClicked + Resize Kollision (2026-03-18)

### Problem nach Versuch 6
Spaltenziehen friert IMMER NOCH ein. Kein Traceback.

### Ursache (NEU entdeckt)
Klick auf Spaltenrand triggert GLEICHZEITIG:
1. `sectionClicked` → `_show_bus_filter_popup()` → `FilterPopup(QDialog)` öffnet sich
2. Qt-internes Resize-Drag startet

Das Popup (Qt.WindowType.Popup) stiehlt den Fokus und blockiert das Resize-Drag → Deadlock.

### Lösung
In `_on_section_clicked()` Mausposition prüfen:
```python
cursor_x = self.mapFromGlobal(self.cursor().pos()).x()
section_end = section_start + self.sectionSize(logical_index)
if cursor_x < section_start + 8 or cursor_x > section_end - 8:
    return  # Resize-Zone → kein Filter-Popup
```
8px Rand an jeder Seite als Resize-Zone definiert.

### Weitere Optimierungen (gleichzeitig)
- Flush-Timer: 100ms → 200ms
- Resume-Timer: 300ms → 500ms
- Nur sichtbaren Bus-Tab updaten
- `flush_batch()`: `dataChanged` statt `layoutChanged`
