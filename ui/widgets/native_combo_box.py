"""NativeComboBox — ComboBox mit paintEvent-Pfeil.

Umgeht qt-material-CSS komplett für den Dropdown-Pfeil.
Der Pfeil wird direkt im paintEvent gezeichnet (wie PyQt-Fluent-Widgets),
dadurch keine Trennlinien- oder Hintergrund-Artefakte.

Verwendung::

    from ui.widgets.native_combo_box import NativeComboBox, NATIVE_COMBO_CSS

    # CSS auf den Parent-Container setzen (überschreibt qt-material):
    toolbar.setStyleSheet(NATIVE_COMBO_CSS)

    # Dann NativeComboBox statt QComboBox verwenden:
    combo = NativeComboBox()
    combo.addItems(['Option A', 'Option B'])

Siehe auch: ``issues/001_combobox_dropdown_arrow_black_line.md``
"""

from PyQt6.QtWidgets import QComboBox
from PyQt6.QtGui import QPainter, QColor
from PyQt6.QtCore import Qt, QPoint

# ── CSS für den Parent-Container ──
# Muss auf dem Container gesetzt werden, NICHT auf einzelnen Widgets.
# Dadurch wird qt-material für alle Kind-ComboBoxen überschrieben.
NATIVE_COMBO_CSS = (
    'QComboBox {'
    '  background: white; color: black;'
    '  border: 1px solid #ababab;'
    '  border-width: 1px; border-radius: 2px;'
    '  border-top-left-radius: 2px; border-top-right-radius: 2px;'
    '  border-bottom-left-radius: 2px; border-bottom-right-radius: 2px;'
    '  border-top: 1px solid #ababab;'
    '  border-bottom: 1px solid #ababab;'
    '  padding: 1px 0px 1px 3px; padding-left: 3px;'
    '  font-size: 11px; height: 18px;'
    '}'
    'QComboBox:hover { background: #f0f0f0; }'
    'QComboBox:focus {'
    '  color: black; border: 1px solid #ababab;'
    '  border-width: 1px;'
    '  border-bottom: 1px solid #ababab;'
    '}'
    'QComboBox::drop-down {'
    '  border: none; width: 16px;'
    '  background: transparent;'
    '}'
    'QComboBox::down-arrow { image: none; width: 0; height: 0; }'
    'QComboBox::down-arrow:focus { image: none; }'
    'QComboBox QLineEdit {'
    '  background: transparent; color: black;'
    '  border: none; border-width: 0px;'
    '  padding: 0px; padding-left: 0px; margin: 0px;'
    '  height: 16px;'
    '  border-radius: 0px;'
    '  border-top-left-radius: 0px; border-top-right-radius: 0px;'
    '}'
    'QComboBox QLineEdit:focus {'
    '  color: black; border: none; border-width: 0px;'
    '}'
    'QComboBox QAbstractItemView {'
    '  background: white; color: black;'
    '  selection-background-color: #e3f2fd;'
    '  border: 1px solid #888888;'
    '  outline: none;'
    '}'
    'QComboBox QAbstractItemView::item {'
    '  height: 20px;'
    '  padding: 1px 4px;'
    '  border: none;'
    '}'
    'QComboBox QAbstractItemView::item:selected {'
    '  background-color: #e3f2fd;'
    '  color: black;'
    '}'
)

# ── Pfeil-Parameter ──
_ARROW_WIDTH = 11        # Dreiecks-Basisbreite (px)
_ARROW_HEIGHT = 6        # Dreiecks-Höhe / Anzahl Zeilen
_ARROW_COLOR = '#555555'
_ARROW_AREA_WIDTH = 15   # Pfeil-Position (letzte 15 px)
_COVER_EXTRA = 5         # Zusätzliche Pixel links abdecken (native Artefakte)
_BG_NORMAL = '#ffffff'
_BG_HOVER = '#f0f0f0'    # Muss mit CSS QComboBox:hover übereinstimmen


def _paint_dropdown_arrow(widget: QComboBox, event):
    """Zeichnet den Dropdown-Pfeil über den nativen Render.

    1. Weißes Rechteck über den Drop-Down-Bereich (deckt Artefakte ab)
    2. 6-Zeilen-Dreieck vertikal + horizontal zentriert
    """
    p = QPainter(widget)
    p.setPen(Qt.PenStyle.NoPen)

    # Hintergrund — breiter als Pfeil-Bereich, um native Artefakte
    # (schwarze Quadrate vom Qt-Fusion-Style) vollständig abzudecken
    bg = QColor(_BG_HOVER) if widget.underMouse() else QColor(_BG_NORMAL)
    p.setBrush(bg)
    cover_x = widget.width() - _ARROW_AREA_WIDTH - _COVER_EXTRA
    cover_w = _ARROW_AREA_WIDTH + _COVER_EXTRA
    p.drawRect(cover_x, 1, cover_w - 1, widget.height() - 2)

    # Dreieck
    x0 = widget.width() - _ARROW_AREA_WIDTH + 2
    y0 = (widget.height() - _ARROW_HEIGHT) // 2
    p.setBrush(QColor(_ARROW_COLOR))
    for row in range(_ARROW_HEIGHT):
        left = x0 + row
        right = x0 + _ARROW_WIDTH - 1 - row
        if left > right:
            break
        p.drawRect(left, y0 + row, right - left + 1, 1)
    p.end()


class NativeComboBox(QComboBox):
    """QComboBox mit nativem Dropdown-Pfeil via paintEvent.

    Der Pfeil wird pixelgenau gezeichnet — kein CSS, kein SVG,
    keine Trennlinien-Artefakte.
    Editable + ReadOnly → gleiche Popup-Rendering wie IpHistoryCombo.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)

    def showPopup(self):
        """Popup-Breite anpassen und unterhalb der ComboBox positionieren."""
        self.setMaxVisibleItems(max(self.count(), 1))
        self.view().setFixedWidth(self.width())
        super().showPopup()
        popup = self.view().parentWidget()
        if popup is not None:
            pos = self.mapToGlobal(QPoint(0, self.height()))
            popup.move(pos)

    def paintEvent(self, event):
        super().paintEvent(event)
        _paint_dropdown_arrow(self, event)
