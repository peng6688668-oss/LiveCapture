"""Zentrales Theme-System für die Messtechnik Plattform.

Bietet Dark- und Light-Modus mit konsistenter Farbpalette,
globales QSS für alle Standard-Widgets und Theme-Persistenz.
"""

from dataclasses import dataclass, field
from typing import List

from PyQt6.QtCore import QObject, QSettings, pyqtSignal
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication


@dataclass
class ColorPalette:
    """Komplette Farbpalette für ein Theme."""

    # Hintergründe
    bg_primary: str = ''
    bg_secondary: str = ''
    bg_tertiary: str = ''
    bg_hover: str = ''
    bg_selected: str = ''

    # Text
    text_primary: str = ''
    text_secondary: str = ''
    text_disabled: str = ''
    text_placeholder: str = ''

    # Ränder
    border: str = ''
    border_light: str = ''
    border_focus: str = ''

    # Akzent & Status
    accent: str = '#e8560a'
    accent_hover: str = ''
    accent_light: str = ''
    accent_muted: str = ''
    success: str = ''
    warning: str = ''
    error: str = ''
    info: str = ''

    # Tabs
    tab_bg: str = ''
    tab_selected: str = ''
    tab_hover: str = ''

    # Header/Toolbar
    header_bg: str = ''
    header_text: str = ''

    # Plot (pyqtgraph)
    plot_bg: str = ''
    plot_grid: str = ''
    plot_text: str = ''


# ── Vordefinierte Paletten ────────────────────────────────────────────

DARK_PALETTE = ColorPalette(
    bg_primary='#1e1e2e',
    bg_secondary='#2a2a3c',
    bg_tertiary='#363649',
    bg_hover='#3d3d56',
    bg_selected='#e8560a22',
    text_primary='#f0f0f0',
    text_secondary='#d0d0d8',
    text_disabled='#b0b0b8',
    text_placeholder='#b8b8c0',
    border='#404055',
    border_light='#333345',
    border_focus='#e8560a',
    accent='#e8560a',
    accent_hover='#ff6b1a',
    accent_light='#e8560a33',
    accent_muted='#f8bc98',
    success='#4caf50',
    warning='#ff9800',
    error='#f44336',
    info='#42a5f5',
    tab_bg='#252538',
    tab_selected='#1e1e2e',
    tab_hover='#333345',
    header_bg='#16162a',
    header_text='#e0e0e8',
    plot_bg='#1e1e2e',
    plot_grid='#404055',
    plot_text='#d0d0d8',
)

LIGHT_PALETTE = ColorPalette(
    bg_primary='#f5f5f7',
    bg_secondary='#ffffff',
    bg_tertiary='#eaeaef',
    bg_hover='#e0e0e8',
    bg_selected='#e8560a18',
    text_primary='#0d0d17',
    text_secondary='#2d2d38',
    text_disabled='#505058',
    text_placeholder='#48484c',
    border='#d0d0d8',
    border_light='#e0e0e8',
    border_focus='#e8560a',
    accent='#e8560a',
    accent_hover='#d04a00',
    accent_light='#e8560a18',
    accent_muted='#e8b8a0',
    success='#2e7d32',
    warning='#e65100',
    error='#c62828',
    info='#1565c0',
    tab_bg='#eaeaef',
    tab_selected='#ffffff',
    tab_hover='#d8d8e0',
    header_bg='#e8e8f0',
    header_text='#15151f',
    plot_bg='#ffffff',
    plot_grid='#d0d0d8',
    plot_text='#2d2d38',
)

# ── Plot-Farben (für Signallinien) ───────────────────────────────────

PLOT_COLORS = [
    '#e8560a', '#42a5f5', '#66bb6a', '#ffa726', '#ab47bc',
    '#ef5350', '#26c6da', '#d4e157', '#ec407a', '#78909c',
    '#8d6e63', '#5c6bc0', '#29b6f6', '#9ccc65', '#ff7043',
    '#7e57c2',
]


def _build_qss(p: ColorPalette) -> str:
    """Erzeugt das komplette QSS-Stylesheet aus einer Palette."""
    # Toolbar-Hover: dezent heller/dunkler als header_bg
    # (gleiche Werte wie Titelleisten-Buttons in _TitleBar)
    is_dark = p.header_bg == '#16162a'
    toolbar_hover = '#3a3a52' if is_dark else '#d0d0dc'
    # Einheitliche Dropdown-Hover-Farbe (dezent dunkler als Hintergrund)
    menu_item_hover = '#3a3a52' if is_dark else '#d8d8e2'
    return f"""
/* ── Basis ────────────────────────────────────────────────── */
QWidget {{
    background-color: {p.bg_primary};
    color: {p.text_primary};
    font-family: 'Segoe UI', 'Ubuntu', sans-serif;
    font-size: 13px;
}}

/* ── QMainWindow ─────────────────────────────────────────── */
QMainWindow {{
    background-color: {p.bg_primary};
}}
QMainWindow::separator {{
    width: 2px;
    background: {p.border};
}}

/* ── QMenuBar / QMenu ────────────────────────────────────── */
QMenuBar {{
    background: {p.header_bg};
    color: {p.header_text};
    padding: 2px;
    border-bottom: 1px solid {p.border};
    font-size: 14px;
    font-weight: normal;
}}
QMenuBar::item {{
    padding: 5px 6px;
    border-radius: 3px;
}}
QMenuBar::item:selected {{
    background: {toolbar_hover};
    color: {p.header_text};
}}
QMenu {{
    background: {p.bg_secondary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    padding: 4px 4px 4px 8px;
    font-size: 14px;
    font-weight: normal;
}}
QMenu::item {{
    padding: 6px 24px 6px 8px;
}}
QMenu::item:selected {{
    background: {menu_item_hover};
    color: {p.text_primary};
}}
QMenu::separator {{
    height: 1px;
    background: {p.border_light};
    margin: 4px 8px;
}}

/* ── QToolBar ────────────────────────────────────────────── */
QToolBar {{
    background: {p.header_bg};
    border-bottom: 1px solid {p.border};
    spacing: 2px;
    padding: 2px 4px;
}}
QToolBar QToolButton {{
    background: transparent;
    color: {p.text_primary};
    padding: 5px 10px;
    font-size: 14px;
    font-weight: normal;
    border-radius: 4px;
    border: none;
}}
QToolBar QToolButton:hover {{
    background: {toolbar_hover};
}}
QToolBar QToolButton:pressed {{
    background: {toolbar_hover};
}}
QToolBar QToolButton::menu-indicator {{
    subcontrol-position: right center;
    width: 10px;
}}

/* ── QTabWidget / QTabBar ────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {p.border};
    border-top: 2px solid {p.accent_muted};
    background: {p.bg_primary};
}}
QTabBar::tab {{
    background: {p.tab_bg};
    color: {p.text_secondary};
    padding: 8px 16px;
    border: 1px solid {p.border};
    border-bottom: none;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}}
QTabBar::tab:selected {{
    background: {p.tab_selected};
    color: {p.accent_muted};
    border-top: 2px solid {p.accent_muted};
    font-weight: bold;
}}
QTabBar::tab:hover:!selected {{
    background: {p.tab_hover};
    color: {p.text_primary};
}}
QTabBar::close-button {{
    subcontrol-position: right;
    padding: 2px;
}}

/* ── QGroupBox ───────────────────────────────────────────── */
QGroupBox {{
    font-weight: bold;
    border: 1px solid {p.border};
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 16px;
    background: {p.bg_secondary};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {p.accent_muted};
}}

/* ── QPushButton ─────────────────────────────────────────── */
QPushButton {{
    background: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    border-radius: 4px;
    padding: 6px 16px;
    font-weight: 500;
}}
QPushButton:hover {{
    background: {p.bg_hover};
    border-color: {p.accent};
}}
QPushButton:pressed, QPushButton:open {{
    background: {p.bg_hover};
}}
QPushButton:disabled {{
    color: {p.text_disabled};
    background: {p.bg_secondary};
    border-color: {p.border_light};
}}
QPushButton[primary="true"] {{
    background: {p.accent};
    color: white;
    border: none;
}}
QPushButton[primary="true"]:hover {{
    background: {p.accent_hover};
}}

/* ── QLineEdit / QTextEdit / QPlainTextEdit ──────────────── */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: {p.accent};
    selection-color: white;
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {p.accent};
}}
QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {{
    color: {p.text_disabled};
    background: {p.bg_secondary};
}}

/* ── QComboBox ───────────────────────────────────────────── */
QComboBox {{
    background: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 20px;
}}
QComboBox:hover {{
    border-color: {p.accent};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {p.text_secondary};
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background: {p.bg_secondary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    selection-background-color: {p.accent};
    selection-color: white;
}}

/* ── QSpinBox / QDoubleSpinBox ───────────────────────────── */
QSpinBox, QDoubleSpinBox {{
    background: {p.bg_tertiary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    border-radius: 4px;
    padding: 4px 8px;
}}
QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {p.accent};
}}
QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background: {p.bg_hover};
    border: none;
    width: 16px;
}}

/* ── QCheckBox / QRadioButton ────────────────────────────── */
QCheckBox {{
    spacing: 6px;
    color: {p.text_primary};
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {p.border};
    border-radius: 3px;
    background: {p.bg_tertiary};
}}
QCheckBox::indicator:checked {{
    background: {p.accent};
    border-color: {p.accent};
}}
QCheckBox::indicator:hover {{
    border-color: {p.accent};
}}
QRadioButton {{
    spacing: 6px;
    color: {p.text_primary};
}}
QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {p.border};
    border-radius: 8px;
    background: {p.bg_tertiary};
}}
QRadioButton::indicator:checked {{
    background: {p.accent};
    border: 3px solid {p.bg_tertiary};
}}

/* ── QTableView / QTreeView / QListView ──────────────────── */
QTableView, QTreeView, QListView {{
    background: {p.bg_primary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    alternate-background-color: {p.bg_secondary};
    gridline-color: {p.border_light};
    selection-background-color: {p.accent};
    selection-color: white;
}}
QTableView::item:hover, QTreeView::item:hover, QListView::item:hover {{
    background: {p.bg_hover};
}}
QHeaderView::section {{
    background: {p.bg_secondary};
    color: {p.text_primary};
    padding: 6px;
    border: none;
    border-bottom: 2px solid {p.accent_muted};
    font-weight: bold;
}}
QHeaderView::section:hover {{
    background: {p.bg_hover};
}}

/* ── QTreeWidget ─────────────────────────────────────────── */
QTreeWidget {{
    background: {p.bg_primary};
    color: {p.text_primary};
    border: 1px solid {p.border};
}}
QTreeWidget::item {{
    padding: 3px 0px;
}}
QTreeWidget::item:selected {{
    background: {p.accent};
    color: white;
}}
QTreeWidget::item:hover:!selected {{
    background: {p.bg_hover};
}}
QTreeWidget::branch:has-children:closed {{
    border-image: none;
}}
QTreeWidget::branch:has-children:open {{
    border-image: none;
}}

/* ── QScrollBar (schmal, modern) ─────────────────────────── */
QScrollBar:vertical {{
    width: 8px;
    background: transparent;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {p.border};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {p.accent};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}
QScrollBar:horizontal {{
    height: 8px;
    background: transparent;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {p.border};
    border-radius: 4px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {p.accent};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ── QProgressBar ────────────────────────────────────────── */
QProgressBar {{
    background: {p.bg_tertiary};
    border: 1px solid {p.border};
    border-radius: 4px;
    text-align: center;
    color: {p.text_primary};
    height: 18px;
}}
QProgressBar::chunk {{
    background: {p.accent};
    border-radius: 3px;
}}

/* ── QSlider ─────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    height: 4px;
    background: {p.border};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {p.accent};
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}
QSlider::handle:horizontal:hover {{
    background: {p.accent_hover};
}}

/* ── QToolTip ────────────────────────────────────────────── */
QToolTip {{
    background: {p.bg_secondary};
    color: {p.text_primary};
    border: 1px solid {p.border};
    padding: 4px 8px;
    border-radius: 3px;
}}

/* ── QSplitter ───────────────────────────────────────────── */
QSplitter::handle {{
    background: {p.border_light};
}}
QSplitter::handle:hover {{
    background: {p.accent};
}}
QSplitter::handle:horizontal {{
    width: 3px;
}}
QSplitter::handle:vertical {{
    height: 3px;
}}

/* ── QStatusBar ──────────────────────────────────────────── */
QStatusBar {{
    background: {p.header_bg};
    color: {p.text_secondary};
    border-top: 1px solid {p.border};
    padding: 2px;
}}
QStatusBar::item {{
    border: none;
}}
QStatusBar QLabel {{
    color: {p.text_secondary};
    padding: 0 4px;
}}

/* ── QDockWidget ─────────────────────────────────────────── */
QDockWidget {{
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}
QDockWidget::title {{
    background: {p.bg_secondary};
    color: {p.text_primary};
    padding: 6px;
    border-bottom: 1px solid {p.border};
}}

/* ── QDialog ─────────────────────────────────────────────── */
QDialog {{
    background: {p.bg_primary};
}}

/* ── QLabel ──────────────────────────────────────────────── */
QLabel {{
    background: transparent;
    color: {p.text_primary};
}}

/* ── QFrame ──────────────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {p.border};
}}

/* ── QStackedWidget ──────────────────────────────────────── */
QStackedWidget {{
    background: {p.bg_primary};
}}

/* ── WelcomePage (eigener paintEvent-Gradient) ───────────── */
#WelcomePage {{
    background: transparent;
}}

/* ── QProgressDialog ─────────────────────────────────────── */
QProgressDialog {{
    background: {p.bg_primary};
}}
"""


class ThemeManager(QObject):
    """Singleton-Manager für das zentrale Theme-System."""

    theme_changed = pyqtSignal(str)  # 'dark' oder 'light'

    _instance = None

    def __init__(self):
        super().__init__()
        self._current_theme = self._load_preference()
        self._palette = DARK_PALETTE if self._current_theme == 'dark' else LIGHT_PALETTE

    @classmethod
    def instance(cls) -> 'ThemeManager':
        """Gibt die Singleton-Instanz zurück."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def current_theme(self) -> str:
        """Gibt den aktuellen Theme-Namen zurück ('dark' oder 'light')."""
        return self._current_theme

    def get_palette(self) -> ColorPalette:
        """Gibt die aktuelle Farbpalette zurück."""
        return self._palette

    def get_plot_colors(self, n: int = 8) -> List[str]:
        """Gibt n distinkte Farben für Plot-Linien zurück."""
        colors = PLOT_COLORS.copy()
        while len(colors) < n:
            colors.extend(PLOT_COLORS)
        return colors[:n]

    def get_status_color(self, status: str) -> str:
        """Gibt die Farbe für einen Status zurück."""
        mapping = {
            'success': self._palette.success,
            'warning': self._palette.warning,
            'error': self._palette.error,
            'info': self._palette.info,
        }
        return mapping.get(status, self._palette.text_primary)

    def apply_theme(self, app: QApplication, theme: str = None):
        """Wendet das Theme auf die gesamte Anwendung an."""
        if theme:
            self._current_theme = theme
        self._palette = DARK_PALETTE if self._current_theme == 'dark' else LIGHT_PALETTE
        self._apply_qpalette(app, self._palette)
        qss = _build_qss(self._palette)
        app.setStyleSheet(qss)
        self._save_preference()

    def toggle_theme(self):
        """Wechselt zwischen Dark und Light."""
        new_theme = 'light' if self._current_theme == 'dark' else 'dark'
        self._current_theme = new_theme
        self._palette = DARK_PALETTE if new_theme == 'dark' else LIGHT_PALETTE

        app = QApplication.instance()
        if app:
            self._apply_qpalette(app, self._palette)
            qss = _build_qss(self._palette)
            app.setStyleSheet(qss)

        self._save_preference()
        self.theme_changed.emit(new_theme)

    @staticmethod
    def _apply_qpalette(app: QApplication, p: ColorPalette):
        """Setzt die Qt-QPalette passend zur Farbpalette.

        Beeinflusst die System-Titelleiste (WSLg/Fusion) und alle
        nativen Widget-Teile, die nicht vom QSS erreicht werden.
        """
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(p.bg_primary))
        pal.setColor(QPalette.ColorRole.WindowText, QColor(p.text_primary))
        pal.setColor(QPalette.ColorRole.Base, QColor(p.bg_tertiary))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(p.bg_secondary))
        pal.setColor(QPalette.ColorRole.Text, QColor(p.text_primary))
        pal.setColor(QPalette.ColorRole.Button, QColor(p.bg_secondary))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor(p.text_primary))
        pal.setColor(QPalette.ColorRole.BrightText, QColor('#ffffff'))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(p.accent))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(p.bg_secondary))
        pal.setColor(QPalette.ColorRole.ToolTipText, QColor(p.text_primary))
        pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(p.text_placeholder))
        pal.setColor(QPalette.ColorRole.Link, QColor(p.accent))
        # Disabled-Zustand
        pal.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.WindowText, QColor(p.text_disabled))
        pal.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.Text, QColor(p.text_disabled))
        pal.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.ButtonText, QColor(p.text_disabled))
        app.setPalette(pal)

    def _save_preference(self):
        """Speichert die Theme-Einstellung persistent."""
        settings = QSettings('MDF4GUI', 'MDF4Viewer')
        settings.setValue('theme', self._current_theme)

    def _load_preference(self) -> str:
        """Lädt die gespeicherte Theme-Einstellung."""
        settings = QSettings('MDF4GUI', 'MDF4Viewer')
        return settings.value('theme', 'dark')
