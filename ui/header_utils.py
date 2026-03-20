"""Gemeinsame Header-Konfiguration für QTreeWidget / QTableWidget.

Stellt sicher, dass alle Spalten-Header einheitlich aussehen:
- Interactive-Modus (Spaltenbreite per Drag änderbar)
- Sichtbare Trennlinien (border-right)
- Visueller Highlight-Balken am Spalten-Rand (WSL2/Wayland-kompatibel)

Verwendung:
    # Einmal beim App-Start aufrufen (z.B. in MainWindow.__init__):
    install_global_resize_cursor(app)

    # Für neue Widgets ohne eigene Header-Konfiguration:
    setup_interactive_header(tree.header())
"""

from PyQt6.QtCore import Qt, QEvent, QObject
from PyQt6.QtWidgets import QHeaderView, QApplication, QFrame

# ── Gemeinsames Stylesheet ───────────────────────────────────────────

_HEADER_STYLE = (
    "QHeaderView::section {"
    "  border-right: 1px solid #606075;"
    "  padding: 4px 6px;"
    "}"
    "QHeaderView::section:last {"
    "  border-right: none;"
    "}"
)

_EDGE_PX = 6  # Pixel-Bereich am Spalten-Rand für Erkennung
_HIGHLIGHT_COLOR = '#1E90FF'
_HIGHLIGHT_W = 3  # Breite des Highlight-Balkens


# ── Globaler Event-Filter für ALLE Header-Viewports ─────────────────

class _GlobalResizeCursorFilter(QObject):
    """App-weiter Event-Filter: Highlight-Balken an QHeaderView-Kanten.

    Verwendet ein leichtgewichtiges QFrame-Overlay auf dem Viewport,
    anstatt direkt im Paint-Event zu zeichnen (PyQt6-kompatibel).
    PyQt6 verbietet obj.event() auf C++-erstellten Viewports.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._styled: set = set()
        self._highlights: dict = {}  # viewport_id → QFrame

    # ── Highlight-Overlay verwalten ─────────────────────────────

    def _get_or_create_highlight(self, viewport):
        """Erstellt oder gibt das QFrame-Overlay für einen Viewport zurück."""
        vp_id = id(viewport)
        line = self._highlights.get(vp_id)
        if line is None:
            line = QFrame(viewport)
            line.setFixedWidth(_HIGHLIGHT_W)
            line.setStyleSheet(f"background-color: {_HIGHLIGHT_COLOR};")
            line.setAttribute(
                Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            line.hide()
            self._highlights[vp_id] = line
        return line

    def _hide_highlight(self, viewport):
        """Versteckt den Highlight-Balken."""
        vp_id = id(viewport)
        line = self._highlights.get(vp_id)
        if line is not None:
            line.hide()

    # ── Event-Filter ────────────────────────────────────────────

    def eventFilter(self, obj, event):
        etype = event.type()

        # MouseLeave / Mausklick → Balken entfernen
        if etype in (QEvent.Type.Leave,
                     QEvent.Type.MouseButtonPress,
                     QEvent.Type.MouseButtonRelease):
            header = obj.parent()
            if isinstance(header, QHeaderView):
                self._hide_highlight(obj)
            return False

        if etype != QEvent.Type.MouseMove:
            return False

        header = obj.parent()
        if not isinstance(header, QHeaderView):
            return False

        # Stylesheet beim ersten Kontakt setzen
        hdr_id = id(header)
        if hdr_id not in self._styled:
            self._styled.add(hdr_id)
            header.setStyleSheet(_HEADER_STYLE)

        # Balken nur bei reinem Hover (keine Maustaste gedrückt)
        if event.buttons() != Qt.MouseButton.NoButton:
            self._hide_highlight(obj)
            return False

        x = int(event.position().x())
        for i in range(header.count() - 1):
            edge = header.sectionPosition(i) + header.sectionSize(i)
            if abs(x - edge) <= _EDGE_PX:
                line = self._get_or_create_highlight(obj)
                line.setGeometry(
                    edge - _HIGHLIGHT_W // 2, 0,
                    _HIGHLIGHT_W, obj.height())
                line.show()
                line.raise_()
                obj.setCursor(Qt.CursorShape.SplitHCursor)
                return False

        # Kein Rand in der Nähe
        self._hide_highlight(obj)
        obj.unsetCursor()
        return False


def install_global_resize_cursor(app: QApplication):
    """Einmal beim App-Start aufrufen — wirkt auf ALLE QHeaderViews."""
    _f = _GlobalResizeCursorFilter(app)
    app.installEventFilter(_f)


# ── Öffentliche Hilfsfunktionen ──────────────────────────────────────

def setup_interactive_header(header: QHeaderView):
    """Header komplett konfigurieren: Interactive + Trennlinien + Cursor.

    Für QTreeWidget:  setup_interactive_header(tree.header())
    Für QTableWidget: setup_interactive_header(table.horizontalHeader())
    """
    header.setStretchLastSection(True)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStyleSheet(_HEADER_STYLE)


def install_resize_cursor(header: QHeaderView):
    """Nur Trennlinien-Stylesheet hinzufügen.

    Für Header, die bereits eine eigene setSectionResizeMode-
    Konfiguration haben (z.B. gemischte Modi pro Spalte).
    """
    header.setStyleSheet(_HEADER_STYLE)
