"""IP-History ComboBox — Wiederverwendbare Komponente für IP-Eingaben.

Speichert eingegebene IP-Adressen/URLs in QSettings und bietet
ein Dropdown mit der Historie an. Unterstützt:
- Globale + Panel-spezifische Historie
- IP-Validierung (IPv4, Hostname, URL) mit rotem Rand bei Fehler
- Rechtsklick → Einzelnen Eintrag oder gesamte Historie löschen
"""

import re

from PyQt6.QtWidgets import QComboBox, QMenu
from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtGui import QAction

from ui.widgets.native_combo_box import _paint_dropdown_arrow

_MAX_HISTORY = 20
_SETTINGS_ORG = 'ViGEM'
_SETTINGS_APP = 'LiveCapture'
_GLOBAL_KEY = 'Global/ip_history'

# IPv4, Hostname, oder URL (vereinfacht)
_IP_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}'           # IPv4
    r'|(\d{1,3}\.){3}\d{1,3}/\d{1,2}'  # IPv4 CIDR
    r'|[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*'  # Hostname
    r'|https?://[^\s]+'                 # URL
    r'|wss?://[^\s]+'                   # WebSocket URL
    r')$'
)

_STYLE_NORMAL = (
    'QLineEdit { border: 1px solid #ababab; background: white;'
    ' color: black; font-size: 11px; }'
)
_STYLE_INVALID = (
    'QLineEdit { border: 2px solid #F44336; background: #FFF3F3;'
    ' color: black; font-size: 11px; }'
)


def _is_valid_entry(value: str) -> bool:
    """Prüft ob der Wert eine gültige IP/Hostname/URL ist."""
    if not value:
        return False
    return _IP_RE.match(value) is not None


class IpHistoryCombo(QComboBox):
    """Editierbarer ComboBox mit IP-Adress-/URL-Historie.

    Parameters
    ----------
    settings_key : str
        Eindeutiger Schlüssel unter dem die Historie gespeichert wird,
        z.B. ``'LoggerDashboard/ip_history'``.
    default_value : str
        Startwert, der im Eingabefeld angezeigt wird.
    placeholder : str
        Platzhaltertext (grau, wenn leer).
    parent : QWidget | None
        Eltern-Widget.
    """

    def __init__(
        self,
        settings_key: str,
        default_value: str = '',
        placeholder: str = '',
        parent=None,
    ):
        super().__init__(parent)
        self._settings_key = settings_key
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        if placeholder:
            self.lineEdit().setPlaceholderText(placeholder)

        # Eingabe-Validierung bei Textänderung
        self.lineEdit().textChanged.connect(self._on_text_changed)

        # Globale + lokale Historie laden und zusammenführen
        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
        local = self._load_list(settings, self._settings_key)
        global_list = self._load_list(settings, _GLOBAL_KEY)

        # Lokal zuerst, dann globale Einträge die nicht lokal sind
        merged = list(local)
        for item in global_list:
            if item not in merged:
                merged.append(item)

        # Default-Wert vorne einfügen falls nicht vorhanden
        if default_value and default_value not in merged:
            merged.insert(0, default_value)

        merged = merged[:_MAX_HISTORY]
        self.addItems(merged)
        if default_value:
            self.setCurrentText(default_value)

        # Rechtsklick-Kontextmenü
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    # ── paintEvent: Pfeil direkt zeichnen (delegiert an Shared-Funktion) ──

    def paintEvent(self, event):
        super().paintEvent(event)
        _paint_dropdown_arrow(self, event)

    def showPopup(self):
        """Popup unterhalb der ComboBox positionieren (wie NativeComboBox)."""
        self.setMaxVisibleItems(min(max(self.count(), 1), 10))
        self.view().setFixedWidth(max(self.width(), 180))
        super().showPopup()
        popup = self.view().parentWidget()
        if popup is not None:
            from PyQt6.QtCore import QPoint
            pos = self.mapToGlobal(QPoint(0, self.height()))
            popup.move(pos)

    # ── Validierung ──

    def _on_text_changed(self, text: str):
        """Zeigt roten Rand bei ungültigem IP-Format."""
        text = text.strip()
        if not text or _is_valid_entry(text):
            self.lineEdit().setStyleSheet(_STYLE_NORMAL)
            self.lineEdit().setToolTip('')
        else:
            self.lineEdit().setStyleSheet(_STYLE_INVALID)
            self.lineEdit().setToolTip(
                'Ungültiges Format. Erwartet: IPv4, Hostname oder URL')

    # ── Öffentliche API ──

    def text(self) -> str:
        """Gibt den aktuellen Text zurück (wie QLineEdit.text())."""
        return self.currentText().strip()

    def save_current(self):
        """Speichert den aktuellen Eintrag in lokale + globale Historie."""
        value = self.currentText().strip()
        if not value:
            return

        # Validierung: nur gültige Einträge speichern
        if not _is_valid_entry(value):
            return

        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)

        # Lokale Historie aktualisieren
        self._save_to_key(settings, self._settings_key, value)

        # Globale Historie aktualisieren
        self._save_to_key(settings, _GLOBAL_KEY, value)

        # ComboBox-Dropdown aktualisieren
        self._refresh_items(settings)

    # ── Kontextmenü ──

    def _show_context_menu(self, pos):
        """Zeigt Kontextmenü mit Einzel-Löschung und Komplett-Löschung."""
        menu = QMenu(self)

        # Einzelne Einträge zum Löschen anbieten
        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
        local = self._load_list(settings, self._settings_key)
        global_list = self._load_list(settings, _GLOBAL_KEY)
        all_items = list(local)
        for item in global_list:
            if item not in all_items:
                all_items.append(item)

        if all_items:
            delete_menu = menu.addMenu('Eintrag löschen')
            for entry in all_items:
                action = QAction(entry, self)
                action.triggered.connect(
                    lambda checked, e=entry: self._delete_single_entry(e))
                delete_menu.addAction(action)
            menu.addSeparator()

        clear_local = QAction('Lokale Historie löschen', self)
        clear_local.triggered.connect(self._clear_local_history)
        menu.addAction(clear_local)

        clear_global = QAction('Globale Historie löschen', self)
        clear_global.triggered.connect(self._clear_global_history)
        menu.addAction(clear_global)

        menu.exec(self.mapToGlobal(pos))

    def _delete_single_entry(self, entry: str):
        """Löscht einen einzelnen Eintrag aus lokaler + globaler Historie."""
        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)

        # Aus lokaler Historie entfernen
        local = self._load_list(settings, self._settings_key)
        if entry in local:
            local.remove(entry)
            settings.setValue(self._settings_key, local)

        # Aus globaler Historie entfernen
        global_list = self._load_list(settings, _GLOBAL_KEY)
        if entry in global_list:
            global_list.remove(entry)
            settings.setValue(_GLOBAL_KEY, global_list)

        current = self.currentText()
        self._refresh_items(settings)
        if current != entry:
            self.setCurrentText(current)

    def _clear_local_history(self):
        """Löscht die Panel-spezifische Historie."""
        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
        settings.setValue(self._settings_key, [])
        current = self.currentText()
        self._refresh_items(settings)
        self.setCurrentText(current)

    def _clear_global_history(self):
        """Löscht die globale Historie."""
        settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
        settings.setValue(_GLOBAL_KEY, [])
        current = self.currentText()
        self._refresh_items(settings)
        self.setCurrentText(current)

    # ── Intern ──

    @staticmethod
    def _load_list(settings: QSettings, key: str) -> list:
        """Lädt eine Liste aus QSettings (robust)."""
        val = settings.value(key, [])
        if isinstance(val, str):
            return [val] if val else []
        if isinstance(val, list):
            return val
        return []

    def _save_to_key(self, settings: QSettings, key: str, value: str):
        """Speichert einen Wert vorne in eine Historie-Liste."""
        items = self._load_list(settings, key)
        if value in items:
            items.remove(value)
        items.insert(0, value)
        items = items[:_MAX_HISTORY]
        settings.setValue(key, items)

    def _refresh_items(self, settings: QSettings):
        """Aktualisiert die ComboBox-Items aus lokaler + globaler Historie."""
        local = self._load_list(settings, self._settings_key)
        global_list = self._load_list(settings, _GLOBAL_KEY)

        merged = list(local)
        for item in global_list:
            if item not in merged:
                merged.append(item)
        merged = merged[:_MAX_HISTORY]

        current = self.currentText()
        self.blockSignals(True)
        self.clear()
        self.addItems(merged)
        self.setCurrentText(current)
        self.blockSignals(False)
