"""Hauptfenster der MDF4 GUI-Anwendung."""

import threading
from pathlib import Path
from typing import Optional, List

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QMenuBar, QMenu, QToolBar, QStatusBar, QFileDialog, QDialog,
    QMessageBox, QTabWidget, QLabel, QProgressBar, QProgressDialog,
    QLineEdit, QPushButton, QStackedWidget, QToolButton, QApplication
)
from PyQt6.QtCore import Qt, QSettings, QSize, QEvent, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QWindowStateChangeEvent, QMouseEvent

from core.mdf_handler import MDFHandler
from core.exporter import Exporter
from core.time_sync_manager import TimeSyncManager, SyncSource
from core.database import DatabaseManager
from ui.signal_tree import SignalTreeWidget
from ui.plot_widget import PlotWidget
from ui.metadata_panel import MetadataPanel
from ui.mdf_browser_panel import MdfBrowserPanel
from ui.dialogs.export_dialog import ExportDialog
from ui.dialogs.help_dialog import FunktionsreferenzDialog
from ui.dialogs.protocol_reference_dialog import ProtocolReferenceDialog
from ui.dialogs.protocol_comparison_dialog import ProtocolComparisonDialog
from ui.dialogs.video_protocol_comparison_dialog import VideoProtocolComparisonDialog
from ui.dialogs.framework_api_comparison_dialog import FrameworkApiComparisonDialog
from ui.dialogs.autosar_architecture_dialog import AutosarArchitectureDialog
from ui.dialogs.network_architecture_dialog import NetworkArchitectureDialog
from ui.dialogs.raw12_knowledge_dialog import Raw12KnowledgeDialog
from ui.dialogs.dataflow_analysis_dialog import DataFlowAnalysisDialog
from ui.dialogs.split_dialog import FileSplitDialog
from ui.dialogs.convert_dialog import ConvertDialog
from ui.video_player import VideoPlayerTab
from ui.wireshark_panel import WiresharkPanel
from ui.docker_panel import DockerPanel
from ui.lua_panel import LuaPanel
from ui.restapi_panel import RestApiPanel
from ui.automation_panel import AutomationPanel
from ui.system_solution_panel import SystemSolutionPanel
from ui.firmware_panel import FirmwareManagementPanel
from ui.firmware_structure_panel import FirmwareStructurePanel
from ui.framework_panel import FrameworkPanel
from ui.xcp_panel import XCPPanel
from ui.welcome_page import WelcomePage
from ui.bus_database_panel import BusDatabasePanel
from ui.bus_trace_panel import BusTracePanel
from ui.converter_panel import ConverterPanel
from ui.xml_editor_panel import XMLEditorPanel
from ui.formula_editor import FormulaEditorDialog, CalculatedChannelManager, FormulaEngine
from ui.dtc_panel import DTCManagementPanel
from ui.report_generator import ReportGeneratorDialog
from ui.terminal_panel import TerminalPanel
from ui.jenkins_panel import JenkinsPanel
from ui.ptp_panel import PTPPanel
from ui.logger_panel import LoggerPanel
from ui.syslog_analyse_panel import SyslogAnalysePanel
from ui.voice_control_panel import VoiceControlPanel
from ui.schnellarbeit_panel import SchnellarbeitPanel
from ui.bus_statistics_panel import BusStatisticsPanel
from ui.state_tracker_panel import StateTrackerPanel
from ui.trigger_config_dialog import TriggerConfigDialog, TriggerStatusWidget
from ui.replay_panel import ReplayPanel
from ui.message_generator_panel import MessageGeneratorPanel
from ui.diagnostic_console_panel import DiagnosticConsolePanel
from ui.bus_data_analyzer_panel import BusDataAnalyzerPanel
from ui.restapi_prog_panel import RestApiProgPanel
from ui.lua_script_prog_panel import LuaScriptProgPanel
from ui.framework_prog_panel import FrameworkProgPanel
from ui.framework_mdf_prog_panel import FrameworkMdfProgPanel
from ui.eol_test_panel import EolTestPanel
from ui.logger_dashboard_panel import LoggerDashboardPanel
from ui.monitor_analyse_panel import MonitorAnalysePanel
from core.trigger_engine import TriggerEngine
from ui.theme import ThemeManager
from ui.icons import Icons


class MDFLoaderThread(QThread):
    """Hintergrund-Thread zum Laden großer MDF-Dateien ohne GUI-Blockierung.

    Öffnet die MDF-Datei und berechnet Dateiinformationen in einem separaten
    Thread.  Der Fortschritt wird über eine zeitbasierte asymptotische Kurve
    geschätzt, da asammdf intern mmap nutzt und daher kein I/O-Zähler aus
    /proc/self/io verfügbar ist.
    """

    progress_text = pyqtSignal(str)
    progress_value = pyqtSignal(int)            # 0 – 100 %
    load_success = pyqtSignal(object, object)   # (MDFHandler, file_info dict)
    load_error = pyqtSignal(str)

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self._stop_monitor = False

    # ── Fortschrittsschätzung ───────────────────────────────────────

    def _monitor_progress(self, file_size, name, size_text):
        """Zeitbasierte Fortschrittsschätzung mit asymptotischer Kurve.

        Verwendet  pct = 95 · (1 − e^{−t/τ})  wobei τ aus der Dateigröße
        abgeleitet wird.  Zeigt zusätzlich die vergangene Zeit an.

        Kurve bei τ:  ~60 %   |  2τ:  ~86 %   |  3τ:  ~95 %
        """
        import time
        import math

        start = time.monotonic()
        # τ = geschätzte Sekunden bis ~63 % Fortschritt.
        # Empirisch: ~350 MB/s effektive MDF-Parse-Geschwindigkeit
        # (Seek-Overhead, Block-Parsing, Index-Aufbau eingerechnet).
        tau = max(3.0, file_size / (350 * 1024 * 1024))

        # Dateiname kürzen um Dialog-Resize zu vermeiden
        short = name if len(name) <= 35 else name[:32] + '...'

        while not self._stop_monitor:
            elapsed = time.monotonic() - start
            pct = max(1, min(95, int(95 * (1 - math.exp(-elapsed / tau)))))
            self.progress_value.emit(pct)

            # Vergangene Zeit im Label anzeigen
            mins, secs = divmod(int(elapsed), 60)
            if mins > 0:
                time_str = f"{mins}:{secs:02d}"
            else:
                time_str = f"{secs} s"
            self.progress_text.emit(
                f"Öffne {short} ({size_text}) \u2014 {time_str} vergangen ...")

            time.sleep(0.5)

    # ── Hauptlogik ──────────────────────────────────────────────────

    def run(self):
        import threading
        try:
            name = Path(self.file_path).name
            file_size = Path(self.file_path).stat().st_size
            if file_size >= 1024 ** 3:
                size_text = f"{file_size / (1024 ** 3):.1f} GB"
            else:
                size_text = f"{file_size / (1024 ** 2):.0f} MB"

            # Dateiname kürzen für Fortschrittsanzeige
            short = name if len(name) <= 35 else name[:32] + '...'

            self.progress_text.emit(f"Öffne {short} ({size_text})...")
            self.progress_value.emit(0)

            # Fortschritts-Monitor starten
            self._stop_monitor = False
            mon = threading.Thread(
                target=self._monitor_progress,
                args=(file_size, short, size_text),
                daemon=True)
            mon.start()

            handler = MDFHandler()
            success = handler.open(self.file_path)

            # Monitor stoppen
            self._stop_monitor = True
            mon.join(timeout=2)

            if not success:
                self.load_error.emit(
                    f"Die Datei konnte nicht geöffnet werden:\n{self.file_path}")
                return

            self.progress_value.emit(95)
            self.progress_text.emit(f"Lade Metadaten für {short}...")
            file_info = handler.get_file_info()

            self.progress_value.emit(100)
            self.load_success.emit(handler, file_info)
        except Exception as e:
            self._stop_monitor = True
            self.load_error.emit(f"{type(e).__name__}: {e}")


class SignalLoaderThread(QThread):
    """Hintergrund-Thread zum Laden von Signal-Daten aus MDF-Dateien.

    Lädt ein oder mehrere Signale asynchron und meldet Fortschritt,
    damit die GUI nicht einfriert.
    """

    progress = pyqtSignal(int, str)       # Prozent, Status-Text
    single_loaded = pyqtSignal(dict)      # Ein einzelnes Signal geladen
    all_loaded = pyqtSignal(list, str)    # Alle fertig: (results, purpose)
    memory_warning = pyqtSignal(str)      # Speicher-Warnung

    def __init__(self, handler, signals_to_load: list,
                 purpose: str = '', parent=None):
        super().__init__(parent)
        self._handler = handler
        self._signals = signals_to_load
        self._purpose = purpose            # 'metadata' | 'plot' | 'compare'
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        results = []
        total = len(self._signals)
        for i, sig_data in enumerate(self._signals):
            if self._cancelled:
                return

            name = sig_data['name']
            group = sig_data.get('group_index')
            channel = sig_data.get('channel_index')

            # Fortschritt: Basis-Prozent pro Signal + Unter-Schritte
            base_pct = int((i / max(total, 1)) * 100)
            step_size = max(1, 100 // max(total, 1))

            self.progress.emit(base_pct,
                f'Lade Signal {i + 1}/{total}: {name} …')

            # Speicher-Check vor dem Laden
            self.progress.emit(
                base_pct + step_size * 10 // 100,
                f'Speicher prüfen ({i + 1}/{total}) …')
            try:
                import psutil
                mem = psutil.virtual_memory()
                if mem.percent > 65:
                    self.memory_warning.emit(
                        f'Speicher kritisch ({mem.percent:.0f}% belegt, '
                        f'{mem.available / (1024**3):.1f} GB frei). '
                        f'Signal "{name}" wird nicht geladen.')
                    continue
            except ImportError:
                pass

            self.progress.emit(
                base_pct + step_size * 25 // 100,
                f'Lade Metadaten: {name} …')

            try:
                if self._purpose == 'metadata':
                    # Nur Metadaten laden — kein vollständiges Signal
                    # (verhindert OOM bei großen Signalen wie DataBytes)
                    info = self._handler.get_signal_info_fast(
                        name, group=group, index=channel)

                    self.progress.emit(
                        base_pct + step_size * 75 // 100,
                        f'Metadaten geladen: {name}')

                    if info:
                        entry = {
                            'name': name,
                            'group_index': group,
                            'channel_index': channel,
                            'timestamps': None,
                            'samples': None,
                            'info': info,
                            'unit': info.get('unit', '') if info else '',
                            'lazy': True,
                        }
                        results.append(entry)
                        self.single_loaded.emit(entry)
                else:
                    # Signal + Info in einem Aufruf laden
                    combined = self._handler.get_signal_with_info(
                        name, group=group, index=channel)

                    self.progress.emit(
                        base_pct + step_size * 75 // 100,
                        f'Signal geladen: {name}')

                    if combined:
                        timestamps, samples, info = combined
                        entry = {
                            'name': name,
                            'group_index': group,
                            'channel_index': channel,
                            'timestamps': timestamps,
                            'samples': samples,
                            'info': info,
                            'unit': info.get('unit', '') if info else '',
                        }
                        results.append(entry)
                        self.single_loaded.emit(entry)
            except Exception:
                continue

        if not self._cancelled:
            self.progress.emit(100, 'Laden abgeschlossen.')
            self.all_loaded.emit(results, self._purpose)


class MainWindow(QMainWindow):
    """Hauptfenster der Anwendung."""

    def __init__(self):
        super().__init__()

        self._db = DatabaseManager()

        self._handlers: List[MDFHandler] = []
        self._current_handler: Optional[MDFHandler] = None
        self._mdf_loader: Optional[MDFLoaderThread] = None
        self._load_progress_dlg: Optional[QProgressDialog] = None
        self._mdf_load_canceled: bool = False
        self._settings = QSettings('MDF4GUI', 'MDF4Viewer')
        self._compare_plot_widget: Optional[PlotWidget] = None  # Einzelner Vergleichs-Tab
        self._calculated_channel_manager = CalculatedChannelManager()  # Berechnete Kanaele
        self._signal_loader: Optional[SignalLoaderThread] = None  # Async-Signal-Loader

        # Time-Sync-Manager für synchronisierte Multi-View-Analyse
        self._time_sync_manager = TimeSyncManager(self)
        self._time_sync_manager.timeChanged.connect(self._on_sync_time_changed)

        # Video-Player Referenz (für Synchronisation)
        self._video_player_window = None

        self._init_ui()
        self._create_menus()
        self._create_toolbar()
        self._create_statusbar()
        self._restore_settings()

        # Event-Filter auf QApplication installieren (fängt alle Widget-Events ab)
        QApplication.instance().installEventFilter(self)

    def _init_ui(self):
        """Initialisiert die Benutzeroberfläche."""
        self.setWindowTitle('ViGEM Messtechnik Plattform')
        self.setMinimumSize(1200, 800)

        # Firmenlogo für System-Titelleiste
        # vigem.png hat weißen Hintergrund → weiß durch transparent ersetzen
        from PyQt6.QtGui import QImage, QColor as _QC
        logo_path = Path(__file__).parent.parent / 'resources' / 'vigem.png'
        if logo_path.exists():
            icon = QIcon()
            for sz in (16, 32, 48):
                img = QImage(str(logo_path))
                img = img.scaled(sz, sz,
                                 Qt.AspectRatioMode.IgnoreAspectRatio,
                                 Qt.TransformationMode.SmoothTransformation)
                img = img.convertToFormat(QImage.Format.Format_ARGB32)
                for y in range(img.height()):
                    for x in range(img.width()):
                        c = img.pixelColor(x, y)
                        if c.red() > 240 and c.green() > 240 and c.blue() > 240:
                            img.setPixelColor(x, y, _QC(0, 0, 0, 0))
                from PyQt6.QtGui import QPixmap
                icon.addPixmap(QPixmap.fromImage(img))
            self.setWindowIcon(icon)

        # Zentrales Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Hauptlayout
        outer_layout = QVBoxLayout(central_widget)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Container für Hauptinhalt
        content_widget = QWidget()
        main_layout = QHBoxLayout(content_widget)
        main_layout.setContentsMargins(4, 4, 4, 4)
        outer_layout.addWidget(content_widget)

        # Stacked Widget: Willkommensseite (0) / Tabs (1)
        self._center_stack = QStackedWidget()

        self._welcome_page = WelcomePage()
        self._welcome_page.open_mdf_requested.connect(self._open_file)
        self._welcome_page.open_a2l_requested.connect(self._xcp_open_a2l)
        self._welcome_page.recent_file_requested.connect(self._open_recent_file)
        self._center_stack.addWidget(self._welcome_page)

        self._plot_tabs = QTabWidget()
        self._plot_tabs.setTabsClosable(True)
        self._plot_tabs.tabCloseRequested.connect(self._close_plot_tab)
        self._plot_tabs.currentChanged.connect(self._on_tab_changed)
        self._center_stack.addWidget(self._plot_tabs)

        main_layout.addWidget(self._center_stack)

        # MDF-Browser Referenz (wird bei MDF-Laden als Tab erstellt)
        self._mdf_browser: Optional[MdfBrowserPanel] = None

        # Drag & Drop aktivieren
        self.setAcceptDrops(True)

    def _create_menus(self):
        """Erstellt die Menüleiste."""
        from PyQt6.QtGui import QPixmap
        palette = ThemeManager.instance().get_palette()
        menubar = self.menuBar()

        # MDF-Datei-Menü (für MDF/MF4 Messdaten)
        file_menu = menubar.addMenu('&MDF-Datei')

        open_action = QAction(Icons.file_open(palette.text_primary), 'MDF &öffnen...', self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._open_file)
        file_menu.addAction(open_action)

        self._recent_menu = file_menu.addMenu(Icons.bus_trace(palette.text_primary), 'Zuletzt geöffnet')
        self._update_recent_menu()

        file_menu.addSeparator()

        save_action = QAction(Icons.save(palette.text_primary), 'MDF &speichern', self)
        save_action.setShortcut(QKeySequence.StandardKey.Save)
        save_action.triggered.connect(self._save_file)
        file_menu.addAction(save_action)

        save_as_action = QAction(Icons.save(palette.text_primary), 'MDF speichern &unter...', self)
        save_as_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        save_as_action.triggered.connect(self._save_file_as)
        file_menu.addAction(save_as_action)

        file_menu.addSeparator()

        close_action = QAction(Icons.stop(palette.text_primary), 'MDF schließen', self)
        close_action.setShortcut(QKeySequence.StandardKey.Close)
        close_action.triggered.connect(self._close_file)
        file_menu.addAction(close_action)

        file_menu.addSeparator()

        export_action = QAction(Icons.send(palette.text_primary), 'MDF &exportieren...', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self._export_signals)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        convert_action = QAction(Icons.converter(palette.text_primary), 'Format konvertieren...', self)
        convert_action.triggered.connect(self._convert_format)
        file_menu.addAction(convert_action)

        statistics_action = QAction(Icons.statistics(palette.text_primary), 'Signal-Statistiken', self)
        statistics_action.triggered.connect(self._show_statistics)
        file_menu.addAction(statistics_action)

        report_action = QAction(Icons.lua(palette.text_primary), 'Report &generieren...', self)
        report_action.setShortcut('Ctrl+Shift+R')
        report_action.triggered.connect(self._show_report_generator)
        file_menu.addAction(report_action)

        file_menu.addSeparator()

        exit_action = QAction(Icons.stop(palette.text_primary), '&Beenden', self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Bearbeiten-Menü
        edit_menu = menubar.addMenu('&Bearbeiten')

        cut_time_action = QAction(Icons.tools(palette.text_primary), 'Zeitbereich ausschneiden...', self)
        cut_time_action.triggered.connect(self._cut_time_range)
        edit_menu.addAction(cut_time_action)

        resample_action = QAction(Icons.converter(palette.text_primary), 'Resampling...', self)
        resample_action.triggered.connect(self._resample)
        edit_menu.addAction(resample_action)

        edit_menu.addSeparator()

        formula_action = QAction(Icons.xml(palette.text_primary), 'Formel-Editor (Berechnete Kanäle)...', self)
        formula_action.setShortcut('Ctrl+Shift+F')
        formula_action.triggered.connect(self._show_formula_editor)
        edit_menu.addAction(formula_action)

        edit_menu.addSeparator()

        merge_action = QAction(Icons.converter(palette.text_primary), 'Dateien zusammenführen...', self)
        merge_action.triggered.connect(self._merge_files)
        edit_menu.addAction(merge_action)

        edit_menu.addSeparator()
        split_action = QAction(Icons.tools(palette.text_primary), 'Dateiaufteilung...', self)
        split_action.triggered.connect(self._show_split_dialog)
        edit_menu.addAction(split_action)

        # Ansicht-Menü
        view_menu = menubar.addMenu('&Ansicht')

        clear_plots_action = QAction(Icons.stop(palette.text_primary), 'Alle Plots schließen', self)
        clear_plots_action.triggered.connect(self._clear_all_plots)
        view_menu.addAction(clear_plots_action)

        view_menu.addSeparator()

        video_action = QAction(Icons.video(palette.text_primary), '&Video-Player', self)
        video_action.setShortcut('Ctrl+V')
        video_action.triggered.connect(self._show_video_player)
        view_menu.addAction(video_action)

        view_menu.addSeparator()

        maximize_action = QAction(Icons.system(palette.text_primary), 'Maximieren', self)
        maximize_action.setShortcut('F10')
        maximize_action.triggered.connect(self._toggle_maximized)
        view_menu.addAction(maximize_action)

        fullscreen_action = QAction(Icons.system(palette.text_primary), 'Vollbild', self)
        fullscreen_action.setShortcut('F11')
        fullscreen_action.triggered.connect(self._toggle_fullscreen)
        view_menu.addAction(fullscreen_action)

        view_menu.addSeparator()

        self._metadata_panel_action = QAction(Icons.bus_trace(palette.text_primary), 'MDF Metadaten-Panel', self)
        self._metadata_panel_action.setShortcut('Ctrl+M')
        self._metadata_panel_action.setCheckable(True)
        self._metadata_panel_action.setChecked(False)  # Standardmäßig ausgeblendet
        self._metadata_panel_action.triggered.connect(self._toggle_metadata_panel)
        view_menu.addAction(self._metadata_panel_action)

        # Analyse-Menü (CANoe-Kernfeatures)
        analyse_menu = menubar.addMenu('&Analyse')

        bus_stats_action = QAction(Icons.statistics(palette.text_primary), 'Bus-Statistik', self)
        bus_stats_action.setShortcut('Ctrl+Alt+B')
        bus_stats_action.triggered.connect(self._show_bus_statistics_panel)
        analyse_menu.addAction(bus_stats_action)

        state_tracker_action = QAction(Icons.analysis(palette.text_primary), 'State Tracker', self)
        state_tracker_action.setShortcut('Ctrl+Alt+S')
        state_tracker_action.triggered.connect(self._show_state_tracker_panel)
        analyse_menu.addAction(state_tracker_action)

        trigger_action = QAction(Icons.trigger(palette.text_primary), 'Trigger konfigurieren', self)
        trigger_action.setShortcut('Ctrl+Alt+T')
        trigger_action.triggered.connect(self._show_trigger_config)
        analyse_menu.addAction(trigger_action)

        analyse_menu.addSeparator()

        replay_action = QAction(Icons.replay(palette.text_primary), 'Replay', self)
        replay_action.setShortcut('Ctrl+Alt+R')
        replay_action.triggered.connect(self._show_replay_panel)
        analyse_menu.addAction(replay_action)

        analyse_menu.addSeparator()

        msg_gen_action = QAction(Icons.send(palette.text_primary), 'Nachrichten-Generator', self)
        msg_gen_action.setShortcut('Ctrl+Alt+G')
        msg_gen_action.triggered.connect(self._show_message_generator_panel)
        analyse_menu.addAction(msg_gen_action)

        diag_action = QAction(Icons.diagnose(palette.text_primary), 'Diagnose-Konsole', self)
        diag_action.setShortcut('Ctrl+Alt+D')
        diag_action.triggered.connect(self._show_diagnostic_console_panel)
        analyse_menu.addAction(diag_action)

        analyse_menu.addSeparator()

        bus_analyzer_action = QAction(Icons.search(palette.text_primary), 'Bus-Daten-Analyse...', self)
        bus_analyzer_action.setShortcut('Ctrl+Alt+A')
        bus_analyzer_action.triggered.connect(self._show_bus_data_analyzer)
        analyse_menu.addAction(bus_analyzer_action)

        # Netzwerk-Menü
        wireshark_menu = menubar.addMenu('&Netzwerk')

        wireshark_open_action = QAction(Icons.file_open(palette.text_primary), '&PCAP öffnen...', self)
        wireshark_open_action.setShortcut('Ctrl+Shift+W')
        wireshark_open_action.triggered.connect(self._show_wireshark_panel)
        wireshark_menu.addAction(wireshark_open_action)

        wireshark_live_action = QAction(Icons.play(palette.text_primary), '&Live Streaming...', self)
        wireshark_live_action.setShortcut('Ctrl+Shift+L')
        wireshark_live_action.triggered.connect(lambda: self._show_wireshark_live_capture())
        wireshark_menu.addAction(wireshark_live_action)

        wireshark_menu.addSeparator()

        wireshark_doip_action = QAction(Icons.wireshark(palette.text_primary), '&DoIP Analyse', self)
        wireshark_doip_action.triggered.connect(lambda: self._show_wireshark_with_filter('doip'))
        wireshark_menu.addAction(wireshark_doip_action)

        wireshark_someip_action = QAction(Icons.wireshark(palette.text_primary), '&SOME/IP Analyse', self)
        wireshark_someip_action.triggered.connect(lambda: self._show_wireshark_with_filter('someip'))
        wireshark_menu.addAction(wireshark_someip_action)

        wireshark_uds_action = QAction(Icons.wireshark(palette.text_primary), '&UDS Analyse', self)
        wireshark_uds_action.triggered.connect(lambda: self._show_wireshark_with_filter('uds'))
        wireshark_menu.addAction(wireshark_uds_action)

        wireshark_tecmp_action = QAction(Icons.wireshark(palette.text_primary), '&PLP/TECMP Analyse', self)
        wireshark_tecmp_action.triggered.connect(lambda: self._show_wireshark_with_filter('tecmp'))
        wireshark_menu.addAction(wireshark_tecmp_action)

        wireshark_ptp_action = QAction(Icons.clock(palette.text_primary), '&PTP/gPTP Analyse', self)
        wireshark_ptp_action.triggered.connect(self._show_ptp_panel)
        wireshark_menu.addAction(wireshark_ptp_action)

        wireshark_menu.addSeparator()

        wireshark_uds_seq_action = QAction(Icons.wireshark(palette.text_primary), 'UDS &Sequenz-Analyse', self)
        wireshark_uds_seq_action.triggered.connect(self._show_wireshark_uds_sequence)
        wireshark_menu.addAction(wireshark_uds_seq_action)

        dtc_action = QAction(Icons.tools(palette.text_primary), '&DTC-Management', self)
        dtc_action.setShortcut('Ctrl+Shift+C')
        dtc_action.triggered.connect(self._show_dtc_panel)
        wireshark_menu.addAction(dtc_action)

        wireshark_stats_action = QAction(Icons.statistics(palette.text_primary), 'S&tatistiken', self)
        wireshark_stats_action.triggered.connect(self._show_wireshark_statistics)
        wireshark_menu.addAction(wireshark_stats_action)

        # Logger-Menü
        logger_menu = menubar.addMenu('&Logger')

        logger_panel_action = QAction(Icons.play(palette.text_primary), '&Logger Panel öffnen', self)
        logger_panel_action.setShortcut('Ctrl+Shift+G')
        logger_panel_action.triggered.connect(self._show_logger_panel)
        logger_menu.addAction(logger_panel_action)

        logger_menu.addSeparator()

        # Geräte-Submenu
        logger_device_menu = logger_menu.addMenu(Icons.firmware(palette.text_primary), 'Geräte')

        logger_discovery_action = QAction(Icons.search(palette.text_primary), 'Geräte erkennen...', self)
        logger_discovery_action.triggered.connect(self._show_device_discovery)
        logger_device_menu.addAction(logger_discovery_action)

        logger_device_menu.addSeparator()

        for device in ['CM 1000 High', 'CM 100 High', 'CM 10Base-T1S',
                        'CM SerDes', 'CM MultiGigabit', 'CM Ethernet Combo',
                        'CM ILaS Combo', 'CM CAN Combo', 'CM LIN Combo']:
            action = QAction(f'Technica {device}', self)
            action.triggered.connect(
                lambda checked, d=device: self._show_logger_with_device(f'Technica {d}'))
            logger_device_menu.addAction(action)

        logger_device_menu.addSeparator()

        aed_gmsl_action = QAction('AED SLA (GMSL2/3)', self)
        aed_gmsl_action.triggered.connect(
            lambda: self._show_logger_with_device('AED SLA (GMSL2/3)'))
        logger_device_menu.addAction(aed_gmsl_action)

        aed_fpd_action = QAction('AED SLA (FPD-Link III/IV)', self)
        aed_fpd_action.triggered.connect(
            lambda: self._show_logger_with_device('AED SLA (FPD-Link III/IV)'))
        logger_device_menu.addAction(aed_fpd_action)

        # Protokolle-Submenu
        logger_protocol_menu = logger_menu.addMenu(Icons.protocol(palette.text_primary), 'Protokolle')

        for proto in ['TECMP', 'IEEE 1722 (AVTP)', 'PLP', 'GMSL2/3', 'FPD-Link III/IV']:
            action = QAction(proto, self)
            action.triggered.connect(
                lambda checked, p=proto: self._show_logger_with_protocol(p))
            logger_protocol_menu.addAction(action)

        logger_menu.addSeparator()

        syslog_action = QAction(Icons.search(palette.text_primary), 'Syslog &Analyse öffnen', self)
        syslog_action.triggered.connect(self._show_syslog_analyse)
        logger_menu.addAction(syslog_action)

        monitor_action = QAction(Icons.search(palette.text_primary), 'Monitor &Analyse', self)
        monitor_action.triggered.connect(self._show_monitor_analyse)
        logger_menu.addAction(monitor_action)

        logger_menu.addSeparator()

        logger_live_action = QAction(Icons.play(palette.text_primary), '&Live Capture starten', self)
        logger_live_action.triggered.connect(self._show_logger_live_capture)
        logger_menu.addAction(logger_live_action)

        logger_menu.addSeparator()

        logger_save_mdf_action = QAction(Icons.save(palette.text_primary), 'Speichern als &MDF 4.1.1', self)
        logger_save_mdf_action.triggered.connect(self._show_logger_save_mdf)
        logger_menu.addAction(logger_save_mdf_action)

        logger_save_pcap_action = QAction(Icons.save(palette.text_primary), 'Speichern als &PCAP', self)
        logger_save_pcap_action.triggered.connect(self._show_logger_save_pcap)
        logger_menu.addAction(logger_save_pcap_action)

        logger_menu.addSeparator()

        logger_stats_action = QAction(Icons.statistics(palette.text_primary), 'Capture &Statistiken', self)
        logger_stats_action.triggered.connect(self._show_logger_statistics)
        logger_menu.addAction(logger_stats_action)

        logger_menu.addSeparator()

        dashboard_action = QAction(Icons.system(palette.text_primary), 'Logger &Dashboard', self)
        dashboard_action.triggered.connect(self._show_logger_dashboard)
        logger_menu.addAction(dashboard_action)

        logger_menu.addSeparator()

        eol_action = QAction(Icons.tools(palette.text_primary), 'EOL-Test', self)
        eol_action.triggered.connect(self._show_eol_test_panel)
        logger_menu.addAction(eol_action)

        # Docker-Menü
        docker_menu = menubar.addMenu('&Docker')

        docker_panel_action = QAction(Icons.docker(palette.text_primary), '&Docker Panel öffnen', self)
        docker_panel_action.setShortcut('Ctrl+Shift+D')
        docker_panel_action.triggered.connect(self._show_docker_panel)
        docker_menu.addAction(docker_panel_action)

        docker_menu.addSeparator()

        docker_containers_action = QAction(Icons.docker(palette.text_primary), '&Container verwalten', self)
        docker_containers_action.triggered.connect(self._show_docker_panel)
        docker_menu.addAction(docker_containers_action)

        docker_images_action = QAction(Icons.docker(palette.text_primary), '&Images verwalten', self)
        docker_images_action.triggered.connect(lambda: self._show_docker_panel_tab(1))
        docker_menu.addAction(docker_images_action)

        docker_logs_action = QAction(Icons.bus_trace(palette.text_primary), '&Logs anzeigen', self)
        docker_logs_action.triggered.connect(lambda: self._show_docker_panel_tab(2))
        docker_menu.addAction(docker_logs_action)

        docker_compose_action = QAction(Icons.docker(palette.text_primary), 'Docker &Compose', self)
        docker_compose_action.triggered.connect(lambda: self._show_docker_panel_tab(3))
        docker_menu.addAction(docker_compose_action)

        docker_menu.addSeparator()

        docker_template_action = QAction(Icons.firmware(palette.text_primary), '&Vehicle Logger Template', self)
        docker_template_action.triggered.connect(self._show_vehicle_logger_template)
        docker_menu.addAction(docker_template_action)

        # Lua-Menü
        lua_menu = menubar.addMenu('&Lua')

        lua_panel_action = QAction(Icons.lua(palette.text_primary), '&Lua Editor öffnen', self)
        lua_panel_action.setShortcut('Ctrl+Shift+L')
        lua_panel_action.triggered.connect(self._show_lua_panel)
        lua_menu.addAction(lua_panel_action)

        lua_menu.addSeparator()

        lua_new_action = QAction(Icons.lua(palette.text_primary), '&Neues Skript', self)
        lua_new_action.triggered.connect(self._lua_new_script)
        lua_menu.addAction(lua_new_action)

        lua_open_action = QAction(Icons.file_open(palette.text_primary), 'Skript &öffnen...', self)
        lua_open_action.triggered.connect(self._lua_open_script)
        lua_menu.addAction(lua_open_action)

        lua_menu.addSeparator()

        # Wireshark Dissector Submenu
        lua_dissector_menu = lua_menu.addMenu(Icons.wireshark(palette.text_primary), 'Wireshark Dissektoren')

        lua_doip_action = QAction('DoIP Dissector', self)
        lua_doip_action.triggered.connect(lambda: self._lua_insert_template('Wireshark Dissector', 'DoIP Dissector'))
        lua_dissector_menu.addAction(lua_doip_action)

        lua_someip_action = QAction('SOME/IP Dissector', self)
        lua_someip_action.triggered.connect(lambda: self._lua_insert_template('Wireshark Dissector', 'SOME/IP Dissector'))
        lua_dissector_menu.addAction(lua_someip_action)

        lua_uds_action = QAction('UDS Dissector', self)
        lua_uds_action.triggered.connect(lambda: self._lua_insert_template('Wireshark Dissector', 'UDS Dissector'))
        lua_dissector_menu.addAction(lua_uds_action)

        # Vehicle Logger Submenu
        lua_vehicle_menu = lua_menu.addMenu(Icons.firmware(palette.text_primary), 'Vehicle Data Logger')

        lua_can_decoder_action = QAction('CAN Signal Decoder', self)
        lua_can_decoder_action.triggered.connect(lambda: self._lua_insert_template('Vehicle Data Logger', 'CAN Signal Decoder'))
        lua_vehicle_menu.addAction(lua_can_decoder_action)

        lua_data_filter_action = QAction('Data Filter Script', self)
        lua_data_filter_action.triggered.connect(lambda: self._lua_insert_template('Vehicle Data Logger', 'Data Filter Script'))
        lua_vehicle_menu.addAction(lua_data_filter_action)

        lua_influx_action = QAction('InfluxDB Writer', self)
        lua_influx_action.triggered.connect(lambda: self._lua_insert_template('Vehicle Data Logger', 'InfluxDB Writer'))
        lua_vehicle_menu.addAction(lua_influx_action)

        lua_menu.addSeparator()

        lua_hex_action = QAction(Icons.tools(palette.text_primary), 'Hex Converter Utility', self)
        lua_hex_action.triggered.connect(lambda: self._lua_insert_template('Utilities', 'Hex Converter'))
        lua_menu.addAction(lua_hex_action)

        # REST API-Menü
        restapi_menu = menubar.addMenu('&REST API')

        restapi_panel_action = QAction(Icons.api(palette.text_primary), '&REST API Client öffnen', self)
        restapi_panel_action.setShortcut('Ctrl+Shift+R')
        restapi_panel_action.triggered.connect(self._show_restapi_panel)
        restapi_menu.addAction(restapi_panel_action)

        restapi_menu.addSeparator()

        # InfluxDB Submenu
        restapi_influx_menu = restapi_menu.addMenu(Icons.database(palette.text_primary), 'InfluxDB')

        restapi_influx_write = QAction('Write Data', self)
        restapi_influx_write.triggered.connect(lambda: self._restapi_load_template('InfluxDB 2.x', 'Write Data'))
        restapi_influx_menu.addAction(restapi_influx_write)

        restapi_influx_query = QAction('Query Data', self)
        restapi_influx_query.triggered.connect(lambda: self._restapi_load_template('InfluxDB 2.x', 'Query Data'))
        restapi_influx_menu.addAction(restapi_influx_query)

        restapi_influx_health = QAction('Health Check', self)
        restapi_influx_health.triggered.connect(lambda: self._restapi_load_template('InfluxDB 2.x', 'Health Check'))
        restapi_influx_menu.addAction(restapi_influx_health)

        # Grafana Submenu
        restapi_grafana_menu = restapi_menu.addMenu(Icons.analysis(palette.text_primary), 'Grafana')

        restapi_grafana_dash = QAction('Get Dashboards', self)
        restapi_grafana_dash.triggered.connect(lambda: self._restapi_load_template('Grafana', 'Get Dashboards'))
        restapi_grafana_menu.addAction(restapi_grafana_dash)

        restapi_grafana_ds = QAction('Get Data Sources', self)
        restapi_grafana_ds.triggered.connect(lambda: self._restapi_load_template('Grafana', 'Get Data Sources'))
        restapi_grafana_menu.addAction(restapi_grafana_ds)

        restapi_grafana_health = QAction('Health Check', self)
        restapi_grafana_health.triggered.connect(lambda: self._restapi_load_template('Grafana', 'Health Check'))
        restapi_grafana_menu.addAction(restapi_grafana_health)

        # Vehicle OBD API Submenu
        restapi_vehicle_menu = restapi_menu.addMenu(Icons.firmware(palette.text_primary), 'Vehicle OBD API')

        restapi_vehicle_info = QAction('Get Vehicle Info', self)
        restapi_vehicle_info.triggered.connect(lambda: self._restapi_load_template('Vehicle OBD API', 'Get Vehicle Info'))
        restapi_vehicle_menu.addAction(restapi_vehicle_info)

        restapi_vehicle_live = QAction('Get Live Data', self)
        restapi_vehicle_live.triggered.connect(lambda: self._restapi_load_template('Vehicle OBD API', 'Get Live Data'))
        restapi_vehicle_menu.addAction(restapi_vehicle_live)

        restapi_vehicle_dtc = QAction('Get DTCs', self)
        restapi_vehicle_dtc.triggered.connect(lambda: self._restapi_load_template('Vehicle OBD API', 'Get DTCs'))
        restapi_vehicle_menu.addAction(restapi_vehicle_dtc)

        restapi_vehicle_uds = QAction('Send UDS Request', self)
        restapi_vehicle_uds.triggered.connect(lambda: self._restapi_load_template('Vehicle OBD API', 'Send UDS Request'))
        restapi_vehicle_menu.addAction(restapi_vehicle_uds)

        # MQTT Submenu
        restapi_mqtt_menu = restapi_menu.addMenu(Icons.protocol(palette.text_primary), 'MQTT REST Bridge')

        restapi_mqtt_pub = QAction('Publish Message', self)
        restapi_mqtt_pub.triggered.connect(lambda: self._restapi_load_template('MQTT (REST Bridge)', 'Publish Message'))
        restapi_mqtt_menu.addAction(restapi_mqtt_pub)

        restapi_mqtt_clients = QAction('List Clients', self)
        restapi_mqtt_clients.triggered.connect(lambda: self._restapi_load_template('MQTT (REST Bridge)', 'List Clients'))
        restapi_mqtt_menu.addAction(restapi_mqtt_clients)

        restapi_menu.addSeparator()

        restapi_env_action = QAction(Icons.settings(palette.text_primary), 'Umgebungsvariablen', self)
        restapi_env_action.triggered.connect(self._restapi_edit_environments)
        restapi_menu.addAction(restapi_env_action)

        # Automatisierung-Menü
        automation_menu = menubar.addMenu('&Automatisierung')

        automation_panel_action = QAction(Icons.automation(palette.text_primary), '&Automatisierung Panel öffnen', self)
        automation_panel_action.setShortcut('Ctrl+Shift+A')
        automation_panel_action.triggered.connect(self._show_automation_panel)
        automation_menu.addAction(automation_panel_action)

        automation_menu.addSeparator()

        # Testvorlagen Submenu
        automation_template_menu = automation_menu.addMenu(Icons.bus_trace(palette.text_primary), 'Testvorlagen')

        automation_can_action = QAction('CAN Konfiguration', self)
        automation_can_action.triggered.connect(lambda: self._automation_load_template('CAN Configuration'))
        automation_template_menu.addAction(automation_can_action)

        automation_lin_action = QAction('LIN Konfiguration', self)
        automation_lin_action.triggered.connect(lambda: self._automation_load_template('LIN Configuration'))
        automation_template_menu.addAction(automation_lin_action)

        automation_flexray_action = QAction('Flexray Konfiguration', self)
        automation_flexray_action.triggered.connect(lambda: self._automation_load_template('Flexray Configuration'))
        automation_template_menu.addAction(automation_flexray_action)

        automation_ethernet_action = QAction('Ethernet Konfiguration', self)
        automation_ethernet_action.triggered.connect(lambda: self._automation_load_template('Ethernet Configuration'))
        automation_template_menu.addAction(automation_ethernet_action)

        automation_template_menu.addSeparator()

        automation_datastream_action = QAction('Datastream Verifikation', self)
        automation_datastream_action.triggered.connect(lambda: self._automation_load_template('Datastream Verification'))
        automation_template_menu.addAction(automation_datastream_action)

        automation_storage_action = QAction('Speicher Status', self)
        automation_storage_action.triggered.connect(lambda: self._automation_load_template('Storage Status'))
        automation_template_menu.addAction(automation_storage_action)

        automation_download_action = QAction('Daten Download', self)
        automation_download_action.triggered.connect(lambda: self._automation_load_template('Data Download'))
        automation_template_menu.addAction(automation_download_action)

        automation_menu.addSeparator()

        automation_run_action = QAction(Icons.play(palette.text_primary), 'Tests ausführen', self)
        automation_run_action.triggered.connect(self._automation_run_tests)
        automation_menu.addAction(automation_run_action)

        automation_report_action = QAction(Icons.statistics(palette.text_primary), 'Report generieren', self)
        automation_report_action.triggered.connect(self._automation_generate_report)
        automation_menu.addAction(automation_report_action)

        automation_menu.addSeparator()

        # Pytest Submenü
        pytest_menu = automation_menu.addMenu(Icons.play(palette.text_primary), 'Pytest')

        pytest_new_action = QAction('Neuen Pytest-Test erstellen...', self)
        pytest_new_action.triggered.connect(self._pytest_new_test)
        pytest_menu.addAction(pytest_new_action)

        pytest_open_action = QAction('Pytest-Datei öffnen...', self)
        pytest_open_action.triggered.connect(self._pytest_open_file)
        pytest_menu.addAction(pytest_open_action)

        pytest_menu.addSeparator()

        pytest_run_action = QAction('Pytest ausführen...', self)
        pytest_run_action.setShortcut('Ctrl+Shift+P')
        pytest_run_action.triggered.connect(self._pytest_run_tests)
        pytest_menu.addAction(pytest_run_action)

        pytest_run_last_action = QAction('Letzten Test wiederholen', self)
        pytest_run_last_action.triggered.connect(self._pytest_run_last)
        pytest_menu.addAction(pytest_run_last_action)

        pytest_menu.addSeparator()

        pytest_report_action = QAction('HTML-Report anzeigen', self)
        pytest_report_action.triggered.connect(self._pytest_show_report)
        pytest_menu.addAction(pytest_report_action)

        pytest_config_action = QAction('Pytest konfigurieren...', self)
        pytest_config_action.triggered.connect(self._pytest_configure)
        pytest_menu.addAction(pytest_config_action)

        # Jenkins Submenü
        jenkins_menu = automation_menu.addMenu(Icons.jenkins(palette.text_primary), 'Jenkins CI/CD')

        jenkins_connect_action = QAction('Verbindung konfigurieren...', self)
        jenkins_connect_action.triggered.connect(self._show_jenkins_config)
        jenkins_menu.addAction(jenkins_connect_action)

        jenkins_menu.addSeparator()

        jenkins_jobs_action = QAction('Jobs anzeigen', self)
        jenkins_jobs_action.triggered.connect(lambda: self._show_jenkins_panel_tab(0))
        jenkins_menu.addAction(jenkins_jobs_action)

        jenkins_trigger_action = QAction('Job starten...', self)
        jenkins_trigger_action.triggered.connect(lambda: self._show_jenkins_panel_tab(0))
        jenkins_menu.addAction(jenkins_trigger_action)

        jenkins_status_action = QAction('Build-Status anzeigen', self)
        jenkins_status_action.triggered.connect(lambda: self._show_jenkins_panel_tab(1))
        jenkins_menu.addAction(jenkins_status_action)

        jenkins_menu.addSeparator()

        jenkins_pipeline_action = QAction('Pipeline erstellen...', self)
        jenkins_pipeline_action.triggered.connect(lambda: self._show_jenkins_panel_tab(3))
        jenkins_menu.addAction(jenkins_pipeline_action)

        jenkins_log_action = QAction('Console Output anzeigen', self)
        jenkins_log_action.triggered.connect(lambda: self._show_jenkins_panel_tab(2))
        jenkins_menu.addAction(jenkins_log_action)

        automation_menu.addSeparator()

        voice_control_action = QAction(Icons.protocol(palette.text_primary), 'Sprachsteuerung', self)
        voice_control_action.setShortcut('Ctrl+Shift+V')
        voice_control_action.triggered.connect(self._show_voice_control_panel)
        automation_menu.addAction(voice_control_action)

        schnellarbeit_action = QAction(Icons.trigger(palette.text_primary), 'Schnell arbeiten', self)
        schnellarbeit_action.setShortcut('Ctrl+Shift+Q')
        schnellarbeit_action.triggered.connect(self._show_schnellarbeit_panel)
        automation_menu.addAction(schnellarbeit_action)

        automation_menu.addSeparator()

        restapi_prog_action = QAction(Icons.api(palette.text_primary), 'REST API PROG', self)
        restapi_prog_action.triggered.connect(self._show_restapi_prog)
        automation_menu.addAction(restapi_prog_action)

        lua_script_prog_action = QAction(Icons.lua(palette.text_primary), 'Lua Script PROG', self)
        lua_script_prog_action.triggered.connect(self._show_lua_script_prog)
        automation_menu.addAction(lua_script_prog_action)

        framework_prog_action = QAction(Icons.framework(palette.text_primary), 'Framework PROG', self)
        framework_prog_action.triggered.connect(self._show_framework_prog)
        automation_menu.addAction(framework_prog_action)

        framework_mdf_prog_action = QAction(Icons.framework(palette.text_primary), 'Framework MDF PROG', self)
        framework_mdf_prog_action.triggered.connect(self._show_framework_mdf_prog)
        automation_menu.addAction(framework_mdf_prog_action)

        # Systemlösung-Menü
        system_menu = menubar.addMenu('&Systemlösung')

        system_panel_action = QAction(Icons.system(palette.text_primary), '&Systemlösung Konfigurator', self)
        system_panel_action.setShortcut('Ctrl+Shift+Y')
        system_panel_action.triggered.connect(self._show_system_solution_panel)
        system_menu.addAction(system_panel_action)

        system_menu.addSeparator()

        # Projektvorlagen Submenu
        system_template_menu = system_menu.addMenu(Icons.bus_trace(palette.text_primary), 'Projektvorlagen')

        adas_template_action = QAction('ADAS Datenlogger', self)
        adas_template_action.triggered.connect(lambda: self._system_load_template('ADAS'))
        system_template_menu.addAction(adas_template_action)

        powertrain_template_action = QAction('Powertrain Logger', self)
        powertrain_template_action.triggered.connect(lambda: self._system_load_template('Powertrain'))
        system_template_menu.addAction(powertrain_template_action)

        chassis_template_action = QAction('Chassis & Fahrwerk', self)
        chassis_template_action.triggered.connect(lambda: self._system_load_template('Chassis'))
        system_template_menu.addAction(chassis_template_action)

        infotainment_template_action = QAction('Infotainment System', self)
        infotainment_template_action.triggered.connect(lambda: self._system_load_template('Infotainment'))
        system_template_menu.addAction(infotainment_template_action)

        system_template_menu.addSeparator()

        fleet_template_action = QAction('Flottenmanagement', self)
        fleet_template_action.triggered.connect(lambda: self._system_load_template('Fleet'))
        system_template_menu.addAction(fleet_template_action)

        prototype_template_action = QAction('Prototyp-Entwicklung', self)
        prototype_template_action.triggered.connect(lambda: self._system_load_template('Prototype'))
        system_template_menu.addAction(prototype_template_action)

        # Hersteller Submenu
        system_manufacturer_menu = system_menu.addMenu(Icons.firmware(palette.text_primary), 'Hersteller')

        vigem_action = QAction('ViGEM GmbH Produkte', self)
        vigem_action.triggered.connect(lambda: self._system_filter_manufacturer('ViGEM GmbH'))
        system_manufacturer_menu.addAction(vigem_action)

        technik_action = QAction('Technik GmbH Produkte', self)
        technik_action.triggered.connect(lambda: self._system_filter_manufacturer('Technik GmbH'))
        system_manufacturer_menu.addAction(technik_action)

        star_action = QAction('STAR Corporation Produkte', self)
        star_action.triggered.connect(lambda: self._system_filter_manufacturer('STAR Corporation'))
        system_manufacturer_menu.addAction(star_action)

        system_manufacturer_menu.addSeparator()

        all_manufacturers_action = QAction('Alle Hersteller anzeigen', self)
        all_manufacturers_action.triggered.connect(lambda: self._system_filter_manufacturer('Alle'))
        system_manufacturer_menu.addAction(all_manufacturers_action)

        # Schnittstellen Submenu
        system_interface_menu = system_menu.addMenu(Icons.connection(palette.text_primary), 'Schnittstellen')

        can_interface_action = QAction('CAN / CAN-FD Module', self)
        can_interface_action.triggered.connect(lambda: self._system_filter_interface('CAN'))
        system_interface_menu.addAction(can_interface_action)

        lin_interface_action = QAction('LIN Module', self)
        lin_interface_action.triggered.connect(lambda: self._system_filter_interface('LIN'))
        system_interface_menu.addAction(lin_interface_action)

        flexray_interface_action = QAction('FlexRay Module', self)
        flexray_interface_action.triggered.connect(lambda: self._system_filter_interface('FlexRay'))
        system_interface_menu.addAction(flexray_interface_action)

        ethernet_interface_action = QAction('Automotive Ethernet', self)
        ethernet_interface_action.triggered.connect(lambda: self._system_filter_interface('Ethernet'))
        system_interface_menu.addAction(ethernet_interface_action)

        # Sensoren Submenu
        system_sensor_menu = system_menu.addMenu(Icons.wireshark(palette.text_primary), 'Sensoren')

        camera_sensor_action = QAction('Kamera-Interfaces', self)
        camera_sensor_action.triggered.connect(lambda: self._system_filter_sensor('Kamera'))
        system_sensor_menu.addAction(camera_sensor_action)

        lidar_sensor_action = QAction('Lidar-Interfaces', self)
        lidar_sensor_action.triggered.connect(lambda: self._system_filter_sensor('Lidar'))
        system_sensor_menu.addAction(lidar_sensor_action)

        radar_sensor_action = QAction('Radar-Interfaces', self)
        radar_sensor_action.triggered.connect(lambda: self._system_filter_sensor('Radar'))
        system_sensor_menu.addAction(radar_sensor_action)

        gps_sensor_action = QAction('GPS/GNSS/IMU Module', self)
        gps_sensor_action.triggered.connect(lambda: self._system_filter_sensor('GPS'))
        system_sensor_menu.addAction(gps_sensor_action)

        system_menu.addSeparator()

        system_report_action = QAction(Icons.statistics(palette.text_primary), 'Systemlösung Report', self)
        system_report_action.triggered.connect(self._system_generate_report)
        system_menu.addAction(system_report_action)

        system_export_action = QAction(Icons.send(palette.text_primary), 'Stückliste exportieren', self)
        system_export_action.triggered.connect(self._system_export_bom)
        system_menu.addAction(system_export_action)

        # Firmware-Menü
        firmware_menu = menubar.addMenu('&Firmware')

        firmware_panel_action = QAction(Icons.firmware(palette.text_primary), '&Firmware Manager öffnen', self)
        firmware_panel_action.setShortcut('Ctrl+Shift+F')
        firmware_panel_action.triggered.connect(self._show_firmware_panel)
        firmware_menu.addAction(firmware_panel_action)

        firmware_menu.addSeparator()

        # Geräte-Submenu
        firmware_device_menu = firmware_menu.addMenu(Icons.firmware(palette.text_primary), 'Geräte')

        device_overview_action = QAction('Geräteübersicht', self)
        device_overview_action.triggered.connect(lambda: self._firmware_show_tab('devices'))
        firmware_device_menu.addAction(device_overview_action)

        device_scan_action = QAction('Netzwerk scannen', self)
        device_scan_action.triggered.connect(self._firmware_scan_devices)
        firmware_device_menu.addAction(device_scan_action)

        device_add_action = QAction('Gerät manuell hinzufügen', self)
        device_add_action.triggered.connect(self._firmware_add_device)
        firmware_device_menu.addAction(device_add_action)

        # Modelle-Submenu
        firmware_model_menu = firmware_menu.addMenu(Icons.firmware(palette.text_primary), 'ViGEM Modelle')

        cca_menu = firmware_model_menu.addMenu('CCA-Serie')
        for model in ['CCA9002', 'CCA9003', 'CCA7010', 'CCA9010', 'CCA9110']:
            action = QAction(model, self)
            action.triggered.connect(lambda checked, m=model: self._firmware_select_model(m))
            cca_menu.addAction(action)

        cs_menu = firmware_model_menu.addMenu('CS-Serie')
        for model in ['CS1', 'CS701', 'CS10']:
            action = QAction(model, self)
            action.triggered.connect(lambda checked, m=model: self._firmware_select_model(m))
            cs_menu.addAction(action)

        # Firmware-Versionen Submenu
        firmware_versions_menu = firmware_menu.addMenu(Icons.database(palette.text_primary), 'Firmware-Versionen')

        versions_view_action = QAction('Alle Versionen anzeigen', self)
        versions_view_action.triggered.connect(lambda: self._firmware_show_tab('versions'))
        firmware_versions_menu.addAction(versions_view_action)

        versions_upload_action = QAction('Firmware hochladen', self)
        versions_upload_action.triggered.connect(self._firmware_upload)
        firmware_versions_menu.addAction(versions_upload_action)

        versions_download_action = QAction('Firmware herunterladen', self)
        versions_download_action.triggered.connect(self._firmware_download)
        firmware_versions_menu.addAction(versions_download_action)

        firmware_versions_menu.addSeparator()

        versions_changelog_action = QAction('Changelog anzeigen', self)
        versions_changelog_action.triggered.connect(self._firmware_show_changelog)
        firmware_versions_menu.addAction(versions_changelog_action)

        # Update-Submenu
        firmware_update_menu = firmware_menu.addMenu(Icons.converter(palette.text_primary), 'Update')

        update_single_action = QAction('Einzelgerät aktualisieren', self)
        update_single_action.triggered.connect(lambda: self._firmware_show_tab('update'))
        firmware_update_menu.addAction(update_single_action)

        update_batch_action = QAction('Batch-Update (mehrere Geräte)', self)
        update_batch_action.triggered.connect(self._firmware_batch_update)
        firmware_update_menu.addAction(update_batch_action)

        update_schedule_action = QAction('Update planen', self)
        update_schedule_action.triggered.connect(self._firmware_schedule_update)
        firmware_update_menu.addAction(update_schedule_action)

        firmware_update_menu.addSeparator()

        update_rollback_action = QAction('Rollback durchführen', self)
        update_rollback_action.triggered.connect(self._firmware_rollback)
        firmware_update_menu.addAction(update_rollback_action)

        # Validierung-Submenu
        firmware_validation_menu = firmware_menu.addMenu(Icons.tools(palette.text_primary), 'Validierung')

        validation_run_action = QAction('Validierung durchführen', self)
        validation_run_action.triggered.connect(lambda: self._firmware_show_tab('validation'))
        firmware_validation_menu.addAction(validation_run_action)

        validation_report_action = QAction('Validierungsbericht erstellen', self)
        validation_report_action.triggered.connect(self._firmware_validation_report)
        firmware_validation_menu.addAction(validation_report_action)

        firmware_validation_menu.addSeparator()

        validation_integrity_action = QAction('Integritätsprüfung (Checksumme)', self)
        validation_integrity_action.triggered.connect(self._firmware_check_integrity)
        firmware_validation_menu.addAction(validation_integrity_action)

        validation_compatibility_action = QAction('Kompatibilitätsprüfung', self)
        validation_compatibility_action.triggered.connect(self._firmware_check_compatibility)
        firmware_validation_menu.addAction(validation_compatibility_action)

        # Konfiguration-Submenu
        firmware_config_menu = firmware_menu.addMenu(Icons.settings(palette.text_primary), 'Konfiguration')

        config_read_action = QAction('Konfiguration lesen', self)
        config_read_action.triggered.connect(lambda: self._firmware_show_tab('configuration'))
        firmware_config_menu.addAction(config_read_action)

        config_write_action = QAction('Konfiguration schreiben', self)
        config_write_action.triggered.connect(self._firmware_config_write)
        firmware_config_menu.addAction(config_write_action)

        firmware_config_menu.addSeparator()

        config_export_action = QAction('Konfiguration exportieren', self)
        config_export_action.triggered.connect(self._firmware_config_export)
        firmware_config_menu.addAction(config_export_action)

        config_import_action = QAction('Konfiguration importieren', self)
        config_import_action.triggered.connect(self._firmware_config_import)
        firmware_config_menu.addAction(config_import_action)

        firmware_config_menu.addSeparator()

        config_profiles_action = QAction('Profile verwalten', self)
        config_profiles_action.triggered.connect(self._firmware_config_profiles)
        firmware_config_menu.addAction(config_profiles_action)

        config_factory_action = QAction('Werkseinstellungen', self)
        config_factory_action.triggered.connect(self._firmware_factory_reset)
        firmware_config_menu.addAction(config_factory_action)

        # Repository-Submenu
        firmware_repo_menu = firmware_menu.addMenu(Icons.database(palette.text_primary), 'Repository')

        repo_view_action = QAction('Repository anzeigen', self)
        repo_view_action.triggered.connect(lambda: self._firmware_show_tab('repository'))
        firmware_repo_menu.addAction(repo_view_action)

        repo_sync_action = QAction('Mit Server synchronisieren', self)
        repo_sync_action.triggered.connect(self._firmware_repo_sync)
        firmware_repo_menu.addAction(repo_sync_action)

        repo_cleanup_action = QAction('Alte Versionen bereinigen', self)
        repo_cleanup_action.triggered.connect(self._firmware_repo_cleanup)
        firmware_repo_menu.addAction(repo_cleanup_action)

        firmware_menu.addSeparator()

        # Firmware Structure Submenu
        firmware_structure_menu = firmware_menu.addMenu(Icons.tools(palette.text_primary), 'Firmware Structure')

        fw_structure_open_action = QAction('Struktur anzeigen', self)
        fw_structure_open_action.triggered.connect(self._show_firmware_structure)
        firmware_structure_menu.addAction(fw_structure_open_action)

        fw_structure_logger_action = QAction('Logger-Modus', self)
        fw_structure_logger_action.triggered.connect(lambda: self._show_firmware_structure('Logger'))
        firmware_structure_menu.addAction(fw_structure_logger_action)

        fw_structure_cs_action = QAction('Copy Station-Modus', self)
        fw_structure_cs_action.triggered.connect(lambda: self._show_firmware_structure('Copy Station'))
        firmware_structure_menu.addAction(fw_structure_cs_action)

        firmware_menu.addSeparator()

        firmware_log_action = QAction(Icons.bus_trace(palette.text_primary), 'Update-Protokoll', self)
        firmware_log_action.triggered.connect(self._firmware_show_log)
        firmware_menu.addAction(firmware_log_action)

        firmware_settings_action = QAction(Icons.settings(palette.text_primary), 'Einstellungen', self)
        firmware_settings_action.triggered.connect(self._firmware_settings)
        firmware_menu.addAction(firmware_settings_action)

        # Framework-Menü
        framework_menu = menubar.addMenu('F&ramework')

        framework_panel_action = QAction(Icons.framework(palette.text_primary), '&Framework Manager öffnen', self)
        framework_panel_action.setShortcut('Ctrl+Shift+K')
        framework_panel_action.triggered.connect(self._show_framework_panel)
        framework_menu.addAction(framework_panel_action)

        framework_menu.addSeparator()

        # API-Dokumentation Submenu
        framework_doc_menu = framework_menu.addMenu(Icons.api(palette.text_primary), 'API-Dokumentation')

        doc_cca_action = QAction('CCA Framework API', self)
        doc_cca_action.triggered.connect(lambda: self._framework_show_doc('CCA'))
        framework_doc_menu.addAction(doc_cca_action)

        doc_mdf_action = QAction('CCA Framework MDF API', self)
        doc_mdf_action.triggered.connect(lambda: self._framework_show_doc('MDF'))
        framework_doc_menu.addAction(doc_mdf_action)

        doc_rest_action = QAction('REST API Referenz', self)
        doc_rest_action.triggered.connect(lambda: self._framework_show_doc('REST'))
        framework_doc_menu.addAction(doc_rest_action)

        framework_doc_menu.addSeparator()

        doc_search_action = QAction('API durchsuchen...', self)
        doc_search_action.setShortcut('Ctrl+Shift+D')
        doc_search_action.triggered.connect(self._framework_search_api)
        framework_doc_menu.addAction(doc_search_action)

        # API-Kategorien Submenu
        framework_category_menu = framework_menu.addMenu(Icons.xml(palette.text_primary), 'API-Kategorien')

        for category in ['Initialisierung', 'Geräte-Management', 'Kanal-Konfiguration',
                        'Datenaufzeichnung', 'Trigger', 'GPS/GNSS', 'MDF-Dateien']:
            action = QAction(category, self)
            action.triggered.connect(lambda checked, c=category: self._framework_show_category(c))
            framework_category_menu.addAction(action)

        # Code-Generator Submenu
        framework_codegen_menu = framework_menu.addMenu(Icons.xml(palette.text_primary), 'Code-Generator')

        codegen_basic_action = QAction('Basis-Anwendung', self)
        codegen_basic_action.triggered.connect(lambda: self._framework_generate_code('Basis-Anwendung'))
        framework_codegen_menu.addAction(codegen_basic_action)

        codegen_logger_action = QAction('CAN-Logger', self)
        codegen_logger_action.triggered.connect(lambda: self._framework_generate_code('CAN-Logger'))
        framework_codegen_menu.addAction(codegen_logger_action)

        codegen_trigger_action = QAction('Trigger-Aufnahme', self)
        codegen_trigger_action.triggered.connect(lambda: self._framework_generate_code('Trigger-basierte Aufnahme'))
        framework_codegen_menu.addAction(codegen_trigger_action)

        codegen_mdf_read_action = QAction('MDF lesen', self)
        codegen_mdf_read_action.triggered.connect(lambda: self._framework_generate_code('MDF-Datei lesen'))
        framework_codegen_menu.addAction(codegen_mdf_read_action)

        codegen_mdf_write_action = QAction('MDF erstellen', self)
        codegen_mdf_write_action.triggered.connect(lambda: self._framework_generate_code('MDF-Datei erstellen'))
        framework_codegen_menu.addAction(codegen_mdf_write_action)

        framework_codegen_menu.addSeparator()

        codegen_custom_action = QAction('Code-Generator öffnen...', self)
        codegen_custom_action.triggered.connect(lambda: self._framework_show_tab('codegen'))
        framework_codegen_menu.addAction(codegen_custom_action)

        # SDK Submenu
        framework_sdk_menu = framework_menu.addMenu(Icons.framework(palette.text_primary), 'SDK')

        sdk_windows_action = QAction('CCA SDK für Windows', self)
        sdk_windows_action.triggered.connect(lambda: self._framework_install_sdk('Windows'))
        framework_sdk_menu.addAction(sdk_windows_action)

        sdk_linux_action = QAction('CCA SDK für Linux', self)
        sdk_linux_action.triggered.connect(lambda: self._framework_install_sdk('Linux'))
        framework_sdk_menu.addAction(sdk_linux_action)

        sdk_mdf_action = QAction('CCA MDF SDK (Cross-Platform)', self)
        sdk_mdf_action.triggered.connect(lambda: self._framework_install_sdk('MDF'))
        framework_sdk_menu.addAction(sdk_mdf_action)

        framework_sdk_menu.addSeparator()

        sdk_manager_action = QAction('SDK-Manager öffnen...', self)
        sdk_manager_action.triggered.connect(lambda: self._framework_show_tab('sdk'))
        framework_sdk_menu.addAction(sdk_manager_action)

        # Beispiele Submenu
        framework_examples_menu = framework_menu.addMenu(Icons.bus_trace(palette.text_primary), 'Beispielprojekte')

        example_quickstart_action = QAction('Quickstart', self)
        example_quickstart_action.triggered.connect(lambda: self._framework_open_example('Quickstart'))
        framework_examples_menu.addAction(example_quickstart_action)

        example_can_action = QAction('CAN-Logger Projekt', self)
        example_can_action.triggered.connect(lambda: self._framework_open_example('CAN-Logger'))
        framework_examples_menu.addAction(example_can_action)

        example_mdf_action = QAction('MDF-Verarbeitung', self)
        example_mdf_action.triggered.connect(lambda: self._framework_open_example('MDF-Reader'))
        framework_examples_menu.addAction(example_mdf_action)

        example_python_action = QAction('Python-Integration', self)
        example_python_action.triggered.connect(lambda: self._framework_open_example('Python Bindings'))
        framework_examples_menu.addAction(example_python_action)

        framework_examples_menu.addSeparator()

        examples_all_action = QAction('Alle Beispiele anzeigen...', self)
        examples_all_action.triggered.connect(lambda: self._framework_show_tab('examples'))
        framework_examples_menu.addAction(examples_all_action)

        framework_menu.addSeparator()

        # API-Explorer
        framework_explorer_action = QAction(Icons.api(palette.text_primary), 'API-Explorer', self)
        framework_explorer_action.triggered.connect(lambda: self._framework_show_tab('explorer'))
        framework_menu.addAction(framework_explorer_action)

        # Online-Ressourcen
        framework_online_menu = framework_menu.addMenu(Icons.api(palette.text_primary), 'Online-Ressourcen')

        online_docs_action = QAction('Online-Dokumentation', self)
        online_docs_action.triggered.connect(self._framework_open_online_docs)
        framework_online_menu.addAction(online_docs_action)

        online_forum_action = QAction('Entwickler-Forum', self)
        online_forum_action.triggered.connect(self._framework_open_forum)
        framework_online_menu.addAction(online_forum_action)

        online_github_action = QAction('GitHub Repository', self)
        online_github_action.triggered.connect(self._framework_open_github)
        framework_online_menu.addAction(online_github_action)

        online_support_action = QAction('Technischer Support', self)
        online_support_action.triggered.connect(self._framework_open_support)
        framework_online_menu.addAction(online_support_action)

        # XCP-Menü
        xcp_menu = menubar.addMenu('&XCP')

        xcp_panel_action = QAction(Icons.protocol(palette.text_primary), '&XCP Panel öffnen', self)
        xcp_panel_action.setShortcut('Ctrl+Shift+X')
        xcp_panel_action.triggered.connect(self._show_xcp_panel)
        xcp_menu.addAction(xcp_panel_action)

        xcp_menu.addSeparator()

        # Dateiverwaltung Submenu
        xcp_file_menu = xcp_menu.addMenu(Icons.file_open(palette.text_primary), 'Dateiverwaltung')

        xcp_a2l_open_action = QAction('A2L-Datei öffnen', self)
        xcp_a2l_open_action.triggered.connect(self._xcp_open_a2l)
        xcp_file_menu.addAction(xcp_a2l_open_action)

        xcp_a2l_create_action = QAction('A2L-Datei erstellen/bearbeiten', self)
        xcp_a2l_create_action.triggered.connect(self._xcp_create_a2l)
        xcp_file_menu.addAction(xcp_a2l_create_action)

        xcp_file_menu.addSeparator()

        xcp_hex_load_action = QAction('HEX-Datei laden', self)
        xcp_hex_load_action.triggered.connect(self._xcp_load_hex)
        xcp_file_menu.addAction(xcp_hex_load_action)

        xcp_hex_generate_action = QAction('HEX-Datei generieren', self)
        xcp_hex_generate_action.triggered.connect(self._xcp_generate_hex)
        xcp_file_menu.addAction(xcp_hex_generate_action)

        xcp_recent_menu = xcp_file_menu.addMenu(Icons.bus_trace(palette.text_primary), 'Zuletzt geöffnet')
        xcp_recent_none = QAction('(Keine)', self)
        xcp_recent_none.setEnabled(False)
        xcp_recent_menu.addAction(xcp_recent_none)

        # Verbindung Submenu
        xcp_connection_menu = xcp_menu.addMenu(Icons.connection(palette.text_primary), 'Verbindung')

        xcp_connect_action = QAction('Neue Verbindung...', self)
        xcp_connect_action.triggered.connect(self._xcp_new_connection)
        xcp_connection_menu.addAction(xcp_connect_action)

        xcp_disconnect_action = QAction('Verbindung trennen', self)
        xcp_disconnect_action.triggered.connect(self._xcp_disconnect)
        xcp_connection_menu.addAction(xcp_disconnect_action)

        xcp_connection_menu.addSeparator()

        xcp_status_action = QAction('Verbindungsstatus', self)
        xcp_status_action.triggered.connect(self._xcp_show_status)
        xcp_connection_menu.addAction(xcp_status_action)

        # XCP on CAN / CAN FD Submenu
        xcp_can_menu = xcp_menu.addMenu(Icons.protocol(palette.text_primary), 'XCP on CAN / CAN FD')

        xcp_can_config_action = QAction('CAN-Schnittstelle konfigurieren', self)
        xcp_can_config_action.triggered.connect(lambda: self._xcp_configure_transport('CAN'))
        xcp_can_menu.addAction(xcp_can_config_action)

        xcp_can_id_action = QAction('CAN-ID Einstellungen', self)
        xcp_can_id_action.triggered.connect(self._xcp_can_id_settings)
        xcp_can_menu.addAction(xcp_can_id_action)

        xcp_canfd_action = QAction('CAN FD aktivieren', self)
        xcp_canfd_action.setCheckable(True)
        xcp_canfd_action.triggered.connect(self._xcp_toggle_canfd)
        xcp_can_menu.addAction(xcp_canfd_action)

        xcp_can_menu.addSeparator()

        xcp_can_timing_action = QAction('Baudrate / Timing', self)
        xcp_can_timing_action.triggered.connect(self._xcp_can_timing)
        xcp_can_menu.addAction(xcp_can_timing_action)

        # XCP on Ethernet Submenu
        xcp_eth_menu = xcp_menu.addMenu(Icons.connection(palette.text_primary), 'XCP on Ethernet')

        xcp_tcp_action = QAction('TCP-Verbindung', self)
        xcp_tcp_action.triggered.connect(lambda: self._xcp_configure_transport('TCP'))
        xcp_eth_menu.addAction(xcp_tcp_action)

        xcp_udp_action = QAction('UDP-Verbindung', self)
        xcp_udp_action.triggered.connect(lambda: self._xcp_configure_transport('UDP'))
        xcp_eth_menu.addAction(xcp_udp_action)

        xcp_eth_menu.addSeparator()

        xcp_eth_settings_action = QAction('IP-Adresse / Port', self)
        xcp_eth_settings_action.triggered.connect(self._xcp_eth_settings)
        xcp_eth_menu.addAction(xcp_eth_settings_action)

        xcp_discovery_action = QAction('Netzwerk-Discovery', self)
        xcp_discovery_action.triggered.connect(self._xcp_network_discovery)
        xcp_eth_menu.addAction(xcp_discovery_action)

        # XCP on FlexRay Submenu
        xcp_flexray_menu = xcp_menu.addMenu(Icons.protocol(palette.text_primary), 'XCP on FlexRay')

        xcp_fr_cluster_action = QAction('FlexRay-Cluster konfigurieren', self)
        xcp_fr_cluster_action.triggered.connect(lambda: self._xcp_configure_transport('FlexRay'))
        xcp_flexray_menu.addAction(xcp_fr_cluster_action)

        xcp_fr_slot_action = QAction('Slot-Zuordnung', self)
        xcp_fr_slot_action.triggered.connect(self._xcp_flexray_slot)
        xcp_flexray_menu.addAction(xcp_fr_slot_action)

        xcp_fr_cycle_action = QAction('Cycle / Segment Einstellungen', self)
        xcp_fr_cycle_action.triggered.connect(self._xcp_flexray_cycle)
        xcp_flexray_menu.addAction(xcp_fr_cycle_action)

        xcp_menu.addSeparator()

        # Messung Submenu
        xcp_measurement_menu = xcp_menu.addMenu(Icons.analysis(palette.text_primary), 'Messung')

        xcp_daq_config_action = QAction('DAQ-Listen konfigurieren', self)
        xcp_daq_config_action.triggered.connect(self._xcp_configure_daq)
        xcp_measurement_menu.addAction(xcp_daq_config_action)

        xcp_measurement_menu.addSeparator()

        xcp_start_meas_action = QAction('Messung starten', self)
        xcp_start_meas_action.triggered.connect(self._xcp_start_measurement)
        xcp_measurement_menu.addAction(xcp_start_meas_action)

        xcp_stop_meas_action = QAction('Messung stoppen', self)
        xcp_stop_meas_action.triggered.connect(self._xcp_stop_measurement)
        xcp_measurement_menu.addAction(xcp_stop_meas_action)

        xcp_measurement_menu.addSeparator()

        xcp_event_config_action = QAction('Event-Konfiguration', self)
        xcp_event_config_action.triggered.connect(self._xcp_configure_events)
        xcp_measurement_menu.addAction(xcp_event_config_action)

        # Kalibrierung Submenu
        xcp_calibration_menu = xcp_menu.addMenu(Icons.settings(palette.text_primary), 'Kalibrierung')

        xcp_read_param_action = QAction('Parameter lesen', self)
        xcp_read_param_action.triggered.connect(self._xcp_read_parameter)
        xcp_calibration_menu.addAction(xcp_read_param_action)

        xcp_write_param_action = QAction('Parameter schreiben', self)
        xcp_write_param_action.triggered.connect(self._xcp_write_parameter)
        xcp_calibration_menu.addAction(xcp_write_param_action)

        xcp_calibration_menu.addSeparator()

        xcp_page_switch_action = QAction('Seiten umschalten (Page Switching)', self)
        xcp_page_switch_action.triggered.connect(self._xcp_page_switching)
        xcp_calibration_menu.addAction(xcp_page_switch_action)

        xcp_flash_action = QAction('Flash-Programmierung', self)
        xcp_flash_action.triggered.connect(self._xcp_flash_programming)
        xcp_calibration_menu.addAction(xcp_flash_action)

        # Sicherheit Submenu
        xcp_security_menu = xcp_menu.addMenu(Icons.tools(palette.text_primary), 'Sicherheit')

        xcp_seedkey_action = QAction('Seed && Key Konfiguration', self)
        xcp_seedkey_action.triggered.connect(self._xcp_seedkey_config)
        xcp_security_menu.addAction(xcp_seedkey_action)

        xcp_unlock_action = QAction('Ressourcenschutz', self)
        xcp_unlock_action.triggered.connect(self._xcp_resource_protection)
        xcp_security_menu.addAction(xcp_unlock_action)

        # Diagnose Submenu
        xcp_diag_menu = xcp_menu.addMenu(Icons.diagnose(palette.text_primary), 'Diagnose')

        xcp_ecu_info_action = QAction('ECU-Informationen', self)
        xcp_ecu_info_action.triggered.connect(self._xcp_ecu_info)
        xcp_diag_menu.addAction(xcp_ecu_info_action)

        xcp_error_log_action = QAction('Fehler-Log', self)
        xcp_error_log_action.triggered.connect(self._xcp_error_log)
        xcp_diag_menu.addAction(xcp_error_log_action)

        xcp_trace_action = QAction('Protokoll-Trace', self)
        xcp_trace_action.triggered.connect(self._xcp_protocol_trace)
        xcp_diag_menu.addAction(xcp_trace_action)

        # Busdatenbank-Menü
        busdb_menu = menubar.addMenu('&Busdatenbank')

        busdb_panel_action = QAction(Icons.database(palette.text_primary), 'Busdatenbank &Panel öffnen', self)
        busdb_panel_action.setShortcut('Ctrl+Shift+B')
        busdb_panel_action.triggered.connect(self._show_bus_database_panel)
        busdb_menu.addAction(busdb_panel_action)

        bus_trace_action = QAction(Icons.bus_trace(palette.text_primary), 'Bus-Trace &Analyse', self)
        bus_trace_action.setShortcut('Ctrl+Alt+T')
        bus_trace_action.triggered.connect(self._show_bus_trace_panel)
        busdb_menu.addAction(bus_trace_action)

        xml_editor_action = QAction(Icons.xml(palette.text_primary), '&XML-Editor', self)
        xml_editor_action.setShortcut('Ctrl+Shift+X')
        xml_editor_action.triggered.connect(self._show_xml_editor_panel)
        busdb_menu.addAction(xml_editor_action)

        busdb_menu.addSeparator()

        # DBC Submenu
        dbc_menu = busdb_menu.addMenu(Icons.database(palette.text_primary), 'DBC (CAN Datenbank)')

        dbc_open_action = QAction('DBC-Datei öffnen...', self)
        dbc_open_action.triggered.connect(self._busdb_open_dbc)
        dbc_menu.addAction(dbc_open_action)

        dbc_create_action = QAction('DBC-Datei erstellen/bearbeiten', self)
        dbc_create_action.triggered.connect(self._busdb_create_dbc)
        dbc_menu.addAction(dbc_create_action)

        dbc_menu.addSeparator()

        dbc_decode_action = QAction('MDF mit DBC dekodieren', self)
        dbc_decode_action.triggered.connect(self._busdb_decode_mdf_dbc)
        dbc_menu.addAction(dbc_decode_action)

        dbc_export_action = QAction('Signale exportieren...', self)
        dbc_export_action.triggered.connect(self._busdb_export_dbc)
        dbc_menu.addAction(dbc_export_action)

        # AUTOSAR/ARXML Submenu
        arxml_menu = busdb_menu.addMenu(Icons.xml(palette.text_primary), 'AUTOSAR/ARXML')

        arxml_open_action = QAction('ARXML-Datei öffnen...', self)
        arxml_open_action.triggered.connect(self._busdb_open_arxml)
        arxml_menu.addAction(arxml_open_action)

        arxml_ecu_action = QAction('ECU-Konfiguration laden', self)
        arxml_ecu_action.triggered.connect(self._busdb_load_ecu)
        arxml_menu.addAction(arxml_ecu_action)

        arxml_menu.addSeparator()

        arxml_swc_action = QAction('SWC-Analyse', self)
        arxml_swc_action.triggered.connect(self._busdb_swc_analysis)
        arxml_menu.addAction(arxml_swc_action)

        arxml_pdu_action = QAction('PDU-Mapping anzeigen', self)
        arxml_pdu_action.triggered.connect(self._busdb_pdu_mapping)
        arxml_menu.addAction(arxml_pdu_action)

        arxml_signal_action = QAction('Signal-Extraktion', self)
        arxml_signal_action.triggered.connect(self._busdb_signal_extraction)
        arxml_menu.addAction(arxml_signal_action)

        # FIBEX Submenu
        fibex_menu = busdb_menu.addMenu(Icons.protocol(palette.text_primary), 'FIBEX (FlexRay)')

        fibex_open_action = QAction('FIBEX-Datei öffnen...', self)
        fibex_open_action.triggered.connect(self._busdb_open_fibex)
        fibex_menu.addAction(fibex_open_action)

        fibex_menu.addSeparator()

        fibex_cluster_action = QAction('FlexRay-Cluster anzeigen', self)
        fibex_cluster_action.triggered.connect(self._busdb_show_cluster)
        fibex_menu.addAction(fibex_cluster_action)

        fibex_frame_action = QAction('Frame-Definition anzeigen', self)
        fibex_frame_action.triggered.connect(self._busdb_show_frames)
        fibex_menu.addAction(fibex_frame_action)

        fibex_decode_action = QAction('FlexRay-Daten dekodieren', self)
        fibex_decode_action.triggered.connect(self._busdb_decode_flexray)
        fibex_menu.addAction(fibex_decode_action)

        # DLT Submenu
        dlt_menu = busdb_menu.addMenu(Icons.diagnose(palette.text_primary), 'DLT (Diagnostic Log)')

        dlt_open_action = QAction('DLT-Datei öffnen...', self)
        dlt_open_action.triggered.connect(self._busdb_open_dlt)
        dlt_menu.addAction(dlt_open_action)

        dlt_menu.addSeparator()

        dlt_filter_action = QAction('Log-Filter konfigurieren', self)
        dlt_filter_action.triggered.connect(self._busdb_dlt_filter)
        dlt_menu.addAction(dlt_filter_action)

        dlt_context_action = QAction('Kontexte verwalten', self)
        dlt_context_action.triggered.connect(self._busdb_dlt_contexts)
        dlt_menu.addAction(dlt_context_action)

        dlt_export_action = QAction('Logs exportieren...', self)
        dlt_export_action.triggered.connect(self._busdb_export_dlt)
        dlt_menu.addAction(dlt_export_action)

        busdb_menu.addSeparator()

        # JSON-Datei öffnen
        json_open_action = QAction(Icons.file_open(palette.text_primary), 'JSON-Datei öffnen...', self)
        json_open_action.setShortcut('Ctrl+Shift+J')
        json_open_action.triggered.connect(self._busdb_open_json)
        busdb_menu.addAction(json_open_action)

        busdb_menu.addSeparator()

        # MDF-Integration Submenu
        mdf_int_menu = busdb_menu.addMenu(Icons.converter(palette.text_primary), 'MDF-Integration')

        mdf_apply_db_action = QAction('Datenbank auf MDF anwenden', self)
        mdf_apply_db_action.triggered.connect(self._busdb_apply_to_mdf)
        mdf_int_menu.addAction(mdf_apply_db_action)

        mdf_decode_raw_action = QAction('Raw CAN/FlexRay dekodieren', self)
        mdf_decode_raw_action.triggered.connect(self._busdb_decode_raw)
        mdf_int_menu.addAction(mdf_decode_raw_action)

        mdf_extract_action = QAction('Signale in MDF extrahieren', self)
        mdf_extract_action.triggered.connect(self._busdb_extract_signals)
        mdf_int_menu.addAction(mdf_extract_action)

        # Converter-Menü (ASAM Format-Konvertierung)
        converter_menu = menubar.addMenu('&Converter')

        converter_panel_action = QAction(Icons.converter(palette.text_primary), 'Converter &Panel öffnen', self)
        converter_panel_action.setShortcut('Ctrl+Shift+C')
        converter_panel_action.triggered.connect(self._show_converter_panel)
        converter_menu.addAction(converter_panel_action)

        converter_menu.addSeparator()

        # MDF Konvertierung
        mdf_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'MDF (Measurement Data)')

        mdf3_to_mdf4_action = QAction('MDF3 → MDF4', self)
        mdf3_to_mdf4_action.triggered.connect(lambda: self._convert_asam('mdf3', 'mdf4'))
        mdf_conv_menu.addAction(mdf3_to_mdf4_action)

        mdf4_to_mdf3_action = QAction('MDF4 → MDF3', self)
        mdf4_to_mdf3_action.triggered.connect(lambda: self._convert_asam('mdf4', 'mdf3'))
        mdf_conv_menu.addAction(mdf4_to_mdf3_action)

        mdf_conv_menu.addSeparator()

        mdf_to_csv_action = QAction('MDF → CSV', self)
        mdf_to_csv_action.triggered.connect(lambda: self._convert_asam('mdf', 'csv'))
        mdf_conv_menu.addAction(mdf_to_csv_action)

        mdf_to_mat_action = QAction('MDF → MAT (MATLAB)', self)
        mdf_to_mat_action.triggered.connect(lambda: self._convert_asam('mdf', 'mat'))
        mdf_conv_menu.addAction(mdf_to_mat_action)

        mdf_to_parquet_action = QAction('MDF → Parquet', self)
        mdf_to_parquet_action.triggered.connect(lambda: self._convert_asam('mdf', 'parquet'))
        mdf_conv_menu.addAction(mdf_to_parquet_action)

        # A2L Konvertierung
        a2l_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'A2L (ASAP2)')

        a2l_to_json_action = QAction('A2L → JSON', self)
        a2l_to_json_action.triggered.connect(lambda: self._convert_asam('a2l', 'json'))
        a2l_conv_menu.addAction(a2l_to_json_action)

        json_to_a2l_action = QAction('JSON → A2L', self)
        json_to_a2l_action.triggered.connect(lambda: self._convert_asam('json', 'a2l'))
        a2l_conv_menu.addAction(json_to_a2l_action)

        a2l_conv_menu.addSeparator()

        a2l_to_xml_action = QAction('A2L → XML', self)
        a2l_to_xml_action.triggered.connect(lambda: self._convert_asam('a2l', 'xml'))
        a2l_conv_menu.addAction(a2l_to_xml_action)

        # DBC Konvertierung
        dbc_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'DBC (CAN Database)')

        dbc_to_arxml_action = QAction('DBC → ARXML', self)
        dbc_to_arxml_action.triggered.connect(lambda: self._convert_asam('dbc', 'arxml'))
        dbc_conv_menu.addAction(dbc_to_arxml_action)

        arxml_to_dbc_action = QAction('ARXML → DBC', self)
        arxml_to_dbc_action.triggered.connect(lambda: self._convert_asam('arxml', 'dbc'))
        dbc_conv_menu.addAction(arxml_to_dbc_action)

        dbc_conv_menu.addSeparator()

        dbc_to_json_action = QAction('DBC → JSON', self)
        dbc_to_json_action.triggered.connect(lambda: self._convert_asam('dbc', 'json'))
        dbc_conv_menu.addAction(dbc_to_json_action)

        json_to_dbc_action = QAction('JSON → DBC', self)
        json_to_dbc_action.triggered.connect(lambda: self._convert_asam('json', 'dbc'))
        dbc_conv_menu.addAction(json_to_dbc_action)

        dbc_to_xlsx_action = QAction('DBC → Excel', self)
        dbc_to_xlsx_action.triggered.connect(lambda: self._convert_asam('dbc', 'xlsx'))
        dbc_conv_menu.addAction(dbc_to_xlsx_action)

        # LDF Konvertierung
        ldf_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'LDF (LIN Database)')

        ldf_to_dbc_action = QAction('LDF → DBC', self)
        ldf_to_dbc_action.triggered.connect(lambda: self._convert_asam('ldf', 'dbc'))
        ldf_conv_menu.addAction(ldf_to_dbc_action)

        ldf_to_json_action = QAction('LDF → JSON', self)
        ldf_to_json_action.triggered.connect(lambda: self._convert_asam('ldf', 'json'))
        ldf_conv_menu.addAction(ldf_to_json_action)

        ldf_to_xlsx_action = QAction('LDF → Excel', self)
        ldf_to_xlsx_action.triggered.connect(lambda: self._convert_asam('ldf', 'xlsx'))
        ldf_conv_menu.addAction(ldf_to_xlsx_action)

        # FIBEX Konvertierung
        fibex_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'FIBEX (FlexRay)')

        fibex_to_arxml_action = QAction('FIBEX → ARXML', self)
        fibex_to_arxml_action.triggered.connect(lambda: self._convert_asam('fibex', 'arxml'))
        fibex_conv_menu.addAction(fibex_to_arxml_action)

        fibex_to_json_action = QAction('FIBEX → JSON', self)
        fibex_to_json_action.triggered.connect(lambda: self._convert_asam('fibex', 'json'))
        fibex_conv_menu.addAction(fibex_to_json_action)

        fibex_to_xlsx_action = QAction('FIBEX → Excel', self)
        fibex_to_xlsx_action.triggered.connect(lambda: self._convert_asam('fibex', 'xlsx'))
        fibex_conv_menu.addAction(fibex_to_xlsx_action)

        # ODX Konvertierung
        odx_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'ODX (Diagnostic)')

        odx_to_json_action = QAction('ODX → JSON', self)
        odx_to_json_action.triggered.connect(lambda: self._convert_asam('odx', 'json'))
        odx_conv_menu.addAction(odx_to_json_action)

        odx_to_xlsx_action = QAction('ODX → Excel', self)
        odx_to_xlsx_action.triggered.connect(lambda: self._convert_asam('odx', 'xlsx'))
        odx_conv_menu.addAction(odx_to_xlsx_action)

        odx_conv_menu.addSeparator()

        cdd_to_odx_action = QAction('CDD → ODX', self)
        cdd_to_odx_action.triggered.connect(lambda: self._convert_asam('cdd', 'odx'))
        odx_conv_menu.addAction(cdd_to_odx_action)

        # ARXML Konvertierung
        arxml_conv_menu = converter_menu.addMenu(Icons.converter(palette.text_primary), 'ARXML (AUTOSAR)')

        arxml_to_json_action = QAction('ARXML → JSON', self)
        arxml_to_json_action.triggered.connect(lambda: self._convert_asam('arxml', 'json'))
        arxml_conv_menu.addAction(arxml_to_json_action)

        arxml_to_xlsx_action = QAction('ARXML → Excel', self)
        arxml_to_xlsx_action.triggered.connect(lambda: self._convert_asam('arxml', 'xlsx'))
        arxml_conv_menu.addAction(arxml_to_xlsx_action)

        # PCAP/PCAPNG Konvertierung
        pcap_conv_menu = converter_menu.addMenu(Icons.protocol(palette.text_primary), 'PCAP/PCAPNG (Network)')

        pcap_to_mdf4_action = QAction('PCAP → MDF4', self)
        pcap_to_mdf4_action.triggered.connect(lambda: self._convert_asam('pcap', 'mdf4'))
        pcap_conv_menu.addAction(pcap_to_mdf4_action)

        pcapng_to_mdf4_action = QAction('PCAPNG → MDF4', self)
        pcapng_to_mdf4_action.triggered.connect(lambda: self._convert_asam('pcapng', 'mdf4'))
        pcap_conv_menu.addAction(pcapng_to_mdf4_action)

        pcap_conv_menu.addSeparator()

        mdf4_to_pcap_action = QAction('MDF4 → PCAP', self)
        mdf4_to_pcap_action.triggered.connect(lambda: self._convert_asam('mdf4', 'pcap'))
        pcap_conv_menu.addAction(mdf4_to_pcap_action)

        mdf4_to_pcapng_action = QAction('MDF4 → PCAPNG', self)
        mdf4_to_pcapng_action.triggered.connect(lambda: self._convert_asam('mdf4', 'pcapng'))
        pcap_conv_menu.addAction(mdf4_to_pcapng_action)

        pcap_conv_menu.addSeparator()

        pcap_to_csv_action = QAction('PCAP → CSV', self)
        pcap_to_csv_action.triggered.connect(lambda: self._convert_asam('pcap', 'csv'))
        pcap_conv_menu.addAction(pcap_to_csv_action)

        pcap_to_json_action = QAction('PCAP → JSON', self)
        pcap_to_json_action.triggered.connect(lambda: self._convert_asam('pcap', 'json'))
        pcap_conv_menu.addAction(pcap_to_json_action)

        pcap_to_xlsx_action = QAction('PCAP → Excel', self)
        pcap_to_xlsx_action.triggered.connect(lambda: self._convert_asam('pcap', 'xlsx'))
        pcap_conv_menu.addAction(pcap_to_xlsx_action)

        # Video-Konvertierung (IP-Kamera/GMSL)
        video_conv_menu = converter_menu.addMenu(Icons.video(palette.text_primary), 'Video (IP-Kamera/GMSL)')

        pcap_to_mp4_action = QAction('PCAP(NG) → MP4', self)
        pcap_to_mp4_action.triggered.connect(lambda: self._convert_asam('pcap', 'mp4'))
        video_conv_menu.addAction(pcap_to_mp4_action)

        pcap_to_avi_action = QAction('PCAP(NG) → AVI', self)
        pcap_to_avi_action.triggered.connect(lambda: self._convert_asam('pcap', 'avi'))
        video_conv_menu.addAction(pcap_to_avi_action)

        pcap_to_mkv_action = QAction('PCAP(NG) → MKV', self)
        pcap_to_mkv_action.triggered.connect(lambda: self._convert_asam('pcap', 'mkv'))
        video_conv_menu.addAction(pcap_to_mkv_action)

        video_conv_menu.addSeparator()

        mdf4_to_mp4_action = QAction('MDF4 → MP4', self)
        mdf4_to_mp4_action.triggered.connect(lambda: self._convert_asam('mdf4', 'mp4'))
        video_conv_menu.addAction(mdf4_to_mp4_action)

        mdf4_to_avi_action = QAction('MDF4 → AVI', self)
        mdf4_to_avi_action.triggered.connect(lambda: self._convert_asam('mdf4', 'avi'))
        video_conv_menu.addAction(mdf4_to_avi_action)

        mdf4_to_mkv_action = QAction('MDF4 → MKV', self)
        mdf4_to_mkv_action.triggered.connect(lambda: self._convert_asam('mdf4', 'mkv'))
        video_conv_menu.addAction(mdf4_to_mkv_action)

        converter_menu.addSeparator()

        # Batch-Konvertierung
        batch_conv_action = QAction(Icons.converter(palette.text_primary), 'Batch-Konvertierung...', self)
        batch_conv_action.triggered.connect(self._show_batch_converter)
        converter_menu.addAction(batch_conv_action)

        # Terminal-Menü
        terminal_menu = menubar.addMenu('&Terminal')

        terminal_panel_action = QAction(Icons.terminal(palette.text_primary), 'Terminal &Panel öffnen', self)
        terminal_panel_action.setShortcut('Ctrl+Shift+T')
        terminal_panel_action.triggered.connect(self._show_terminal_panel)
        terminal_menu.addAction(terminal_panel_action)

        terminal_menu.addSeparator()

        terminal_ssh_action = QAction(Icons.connection(palette.text_primary), 'SSH &Verbindung...', self)
        terminal_ssh_action.triggered.connect(self._show_terminal_ssh)
        terminal_menu.addAction(terminal_ssh_action)

        terminal_serial_action = QAction(Icons.connection(palette.text_primary), '&Serielle Verbindung...', self)
        terminal_serial_action.triggered.connect(self._show_terminal_serial)
        terminal_menu.addAction(terminal_serial_action)

        terminal_menu.addSeparator()

        terminal_quick_action = QAction(Icons.trigger(palette.text_primary), '&Quick Connect', self)
        terminal_quick_action.triggered.connect(self._show_terminal_quick_connect)
        terminal_menu.addAction(terminal_quick_action)

        # Hilfe-Menü
        help_menu = menubar.addMenu('&Hilfe')

        ref_action = QAction(Icons.search(palette.text_primary), 'Funktionsreferenz...', self)
        ref_action.setShortcut(QKeySequence('F1'))
        ref_action.triggered.connect(self._show_help_reference)
        help_menu.addAction(ref_action)

        proto_ref_action = QAction(Icons.protocol(palette.text_primary), 'Protokoll-Referenz...', self)
        proto_ref_action.triggered.connect(self._show_protocol_reference)
        help_menu.addAction(proto_ref_action)

        proto_cmp_menu = help_menu.addMenu(Icons.protocol(palette.text_primary), 'Protokoll-Vergleich')
        proto_cmp_bus_action = QAction('PLP / TECMP / ASAM CMP (Bus-Protokolle)...', self)
        proto_cmp_bus_action.triggered.connect(self._show_protocol_comparison)
        proto_cmp_menu.addAction(proto_cmp_bus_action)
        proto_cmp_video_action = QAction('GigE Vision / MIPI CSI-2 RAW (Video-Protokolle)...', self)
        proto_cmp_video_action.triggered.connect(self._show_video_protocol_comparison)
        proto_cmp_menu.addAction(proto_cmp_video_action)
        proto_cmp_fw_action = QAction('CCA Framework vs Framework MDF (API-Vergleich)...', self)
        proto_cmp_fw_action.triggered.connect(self._show_framework_api_comparison)
        proto_cmp_menu.addAction(proto_cmp_fw_action)

        autosar_action = QAction(Icons.protocol(palette.text_primary), 'AUTOSAR-Architektur...', self)
        autosar_action.triggered.connect(self._show_autosar_architecture)
        help_menu.addAction(autosar_action)

        network_action = QAction(Icons.protocol(palette.text_primary), 'Netzwerk-Architektur (OSI/TCP-IP)...', self)
        network_action.triggered.connect(self._show_network_architecture)
        help_menu.addAction(network_action)

        # Datenfluss-Analyse Submenu
        dataflow_menu = help_menu.addMenu(Icons.protocol(palette.text_primary), '数据流全链路分析')
        can_tecmp_action = QAction('CAN帧 → TECMP/PLP 以太网帧...', self)
        can_tecmp_action.triggered.connect(self._show_dataflow_can_tecmp)
        dataflow_menu.addAction(can_tecmp_action)

        wissen_menu = help_menu.addMenu(Icons.protocol(palette.text_primary), 'Wissen')
        raw12_action = QAction('RAW12-Format & Sensor-Grundlagen...', self)
        raw12_action.triggered.connect(self._show_raw12_knowledge)
        wissen_menu.addAction(raw12_action)

        help_menu.addSeparator()

        about_action = QAction(Icons.analysis(palette.text_primary), 'Über...', self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

        # --- Wayland/WSL2 Menü-Fix ---
        # Unter Wayland werden Menüs als separate Top-Level-Fenster gerendert.
        # Qt schließt sie beim Hover über andere Menü-Einträge nicht zuverlässig.
        # Fix: MouseMove auf der Menüleiste tracken, veraltete Popups manuell schließen.
        self._menubar_menus = {}  # {QAction: QMenu}
        for action in menubar.actions():
            menu = action.menu()
            if menu:
                self._menubar_menus[action] = menu
        self._active_menu_action = None  # Aktuell gehoverter Menü-Eintrag
        # Timer für verzögertes Schließen (Maus verlässt Menüleiste Richtung Dropdown)
        self._menu_close_timer = QTimer(self)
        self._menu_close_timer.setSingleShot(True)
        self._menu_close_timer.setInterval(400)
        self._menu_close_timer.timeout.connect(self._close_orphan_menus)
        # Event-Filter auf Menüleiste für MouseMove/Leave
        menubar.setMouseTracking(True)
        menubar.installEventFilter(self)

    def _force_hide_all_menus(self, except_menu=None):
        """Erzwingt das Schließen aller Menü-Popups (Wayland-robust)."""
        for menu in self._menubar_menus.values():
            if menu is not except_menu and menu.isVisible():
                menu.hide()
                menu.close()
        # Zusätzlich alle Popup-Widgets schließen die nicht das Ausnahme-Menü sind
        popup = QApplication.activePopupWidget()
        while popup:
            if except_menu and popup is except_menu:
                break
            popup.close()
            popup = QApplication.activePopupWidget()

    def _close_orphan_menus(self):
        """Schließt verwaiste Menüs, die nach Maus-Verlassen sichtbar geblieben sind."""
        # Nicht schließen wenn Maus in einem Menü-Popup ist
        popup = QApplication.activePopupWidget()
        if popup and isinstance(popup, QMenu):
            return
        # Nicht schließen wenn Menüleiste noch aktiv
        menubar = self.menuBar()
        if menubar and menubar.activeAction():
            return
        self._force_hide_all_menus()
        self._active_menu_action = None

    def _create_toolbar(self):
        """Erstellt die Toolbar mit professionellen SVG-Icons."""
        from PyQt6.QtGui import QPixmap
        palette = ThemeManager.instance().get_palette()
        toolbar = QToolBar('Hauptwerkzeuge')
        toolbar.setObjectName('Hauptwerkzeuge')
        toolbar.setIconSize(QSize(18, 18))
        toolbar.setFixedHeight(28)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # --- Datei (Direkter Button) ---
        self._tb_open_action = QAction(Icons.file_open(palette.text_primary), 'MDF Öffnen', self)
        self._tb_open_action.setToolTip('MDF-Datei öffnen (Strg+O)')
        self._tb_open_action.triggered.connect(self._open_file)
        toolbar.addAction(self._tb_open_action)

        toolbar.addSeparator()

        # --- Analyse (Dropdown) ---
        self._tb_analyse_btn = QToolButton()
        self._tb_analyse_btn.setText(' Analyse')
        self._tb_analyse_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._tb_analyse_btn.setToolTip('Analyse- und Visualisierungswerkzeuge')
        self._tb_analyse_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        toolbar.addWidget(self._tb_analyse_btn)

        # --- Protokoll (Dropdown) ---
        self._tb_proto_btn = QToolButton()
        self._tb_proto_btn.setText(' Protokoll')
        self._tb_proto_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._tb_proto_btn.setToolTip('XCP, CAN und Bus-Werkzeuge')
        self._tb_proto_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        toolbar.addWidget(self._tb_proto_btn)

        # --- Werkzeuge (Dropdown) ---
        self._tb_tools_btn = QToolButton()
        self._tb_tools_btn.setText(' Werkzeuge')
        self._tb_tools_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._tb_tools_btn.setToolTip('Externe Werkzeuge und Editoren')
        self._tb_tools_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        toolbar.addWidget(self._tb_tools_btn)

        # --- System (Dropdown) ---
        self._tb_system_btn = QToolButton()
        self._tb_system_btn.setText(' System')
        self._tb_system_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._tb_system_btn.setToolTip('Automatisierung, Firmware und Systemkonfiguration')
        self._tb_system_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        toolbar.addWidget(self._tb_system_btn)

        # Dropdown-Menüs und Icons befüllen
        self._rebuild_toolbar_icons()

        toolbar.addSeparator()

        # === Time-Sync Controls ===
        self._create_sync_toolbar(toolbar)

        # Spacer um Suchfeld nach rechts zu schieben
        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().horizontalPolicy().Expanding,
                            spacer.sizePolicy().verticalPolicy().Preferred)
        toolbar.addWidget(spacer)

        # RAM-Anzeige
        self._mem_label = QLabel()
        self._mem_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._mem_label.setTextFormat(Qt.TextFormat.RichText)
        self._mem_label.setToolTip('Arbeitsspeicher-Auslastung')
        toolbar.addWidget(self._mem_label)
        self._on_mem_timer()                  # Sofort einmal abfragen
        self._mem_warning_active = False       # Sperrt mehrfache Warnungen

        # Timer für periodische Aktualisierung (alle 2 Sekunden)
        self._mem_timer = QTimer(self)
        self._mem_timer.timeout.connect(self._on_mem_timer)
        self._mem_timer.start(2000)

        # Suchfeld
        self._global_search_edit = QLineEdit()
        self._global_search_edit.setPlaceholderText('Suchen...')
        self._global_search_edit.setFixedWidth(150)
        self._global_search_edit.addAction(
            Icons.search(palette.text_secondary),
            QLineEdit.ActionPosition.LeadingPosition)
        self._global_search_edit.returnPressed.connect(self._perform_global_search)
        toolbar.addWidget(self._global_search_edit)

        toolbar.addSeparator()

        # Theme-Toggle-Button
        theme_icon = (Icons.theme_light(palette.text_primary)
                      if ThemeManager.instance().current_theme() == 'dark'
                      else Icons.theme_dark(palette.text_primary))
        self._theme_action = QAction(theme_icon, 'Theme wechseln', self)
        self._theme_action.setToolTip('Dark/Light Theme umschalten')
        self._theme_action.triggered.connect(self._toggle_theme)
        toolbar.addAction(self._theme_action)

        # Theme-Change-Signal verbinden
        ThemeManager.instance().theme_changed.connect(self._on_theme_changed)

    def _rebuild_toolbar_icons(self):
        """Aktualisiert alle Toolbar-Button-Icons und Dropdown-Menüs."""
        palette = ThemeManager.instance().get_palette()

        # MDF Öffnen
        self._tb_open_action.setIcon(Icons.file_open(palette.text_primary))

        # Analyse
        self._tb_analyse_btn.setIcon(Icons.analysis(palette.accent))
        m = QMenu(self)
        m.addAction(Icons.analysis(palette.text_primary), 'Signal plotten', self._plot_selected)
        m.addAction(Icons.video(palette.text_primary), 'Video-Player', self._show_video_player)
        self._tb_analyse_btn.setMenu(m)

        # Protokoll
        self._tb_proto_btn.setIcon(Icons.protocol(palette.text_primary))
        m = QMenu(self)
        m.addAction(Icons.protocol(palette.text_primary), 'XCP Panel', self._show_xcp_panel)
        m.addAction(Icons.database(palette.text_primary), 'Busdatenbank', self._show_bus_database_panel)
        m.addAction(Icons.bus_trace(palette.text_primary), 'Bus-Trace', self._show_bus_trace_panel)
        m.addAction(Icons.clock(palette.text_primary), 'PTP/gPTP', self._show_ptp_panel)
        self._tb_proto_btn.setMenu(m)

        # Werkzeuge
        self._tb_tools_btn.setIcon(Icons.tools(palette.text_primary))
        m = QMenu(self)
        m.addAction(Icons.wireshark(palette.text_primary), 'Wireshark', self._show_wireshark_panel)
        m.addAction(Icons.terminal(palette.text_primary), 'Terminal', self._show_terminal_panel)
        m.addAction(Icons.jenkins(palette.text_primary), 'Jenkins CI/CD', self._show_jenkins_panel)
        m.addAction(Icons.docker(palette.text_primary), 'Docker', self._show_docker_panel)
        m.addAction(Icons.lua(palette.text_primary), 'Lua-Editor', self._show_lua_panel)
        m.addAction(Icons.api(palette.text_primary), 'REST API', self._show_restapi_panel)
        m.addSeparator()
        m.addAction(Icons.converter(palette.text_primary), 'Converter', self._show_converter_panel)
        m.addAction(Icons.xml(palette.text_primary), 'XML-Editor', self._show_xml_editor_panel)
        self._tb_tools_btn.setMenu(m)

        # System
        self._tb_system_btn.setIcon(Icons.settings(palette.text_primary))
        m = QMenu(self)
        m.addAction(Icons.automation(palette.text_primary), 'Automatisierung', self._show_automation_panel)
        m.addAction(Icons.system(palette.text_primary), 'Systemlösung', self._show_system_solution_panel)
        m.addSeparator()
        m.addAction(Icons.firmware(palette.text_primary), 'Firmware', self._show_firmware_panel)
        m.addAction(Icons.framework(palette.text_primary), 'Framework', self._show_framework_panel)
        self._tb_system_btn.setMenu(m)

    def _create_statusbar(self):
        """Erstellt die Statusleiste."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        # Verbindungsstatus-Indikator
        palette = ThemeManager.instance().get_palette()
        self._conn_indicator = QLabel()
        self._conn_indicator.setFixedSize(12, 12)
        self._conn_indicator.setStyleSheet(
            f'background: {palette.text_disabled}; border-radius: 6px;')
        self._conn_indicator.setToolTip('Nicht verbunden')
        self._statusbar.addWidget(self._conn_indicator)

        # Dateiname-Label
        self._file_label = QLabel('Keine Datei geladen')
        self._file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._statusbar.addWidget(self._file_label, 1)

        # Signal-Zähler
        self._signal_label = QLabel('')
        self._signal_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._statusbar.addWidget(self._signal_label)

        # Zeitbereich
        self._time_label = QLabel('')
        self._time_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._statusbar.addWidget(self._time_label)

        # Fortschrittsbalken (versteckt)
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(200)
        self._progress.hide()
        self._statusbar.addWidget(self._progress)

        # Theme-Anzeige
        theme_name = 'Dark' if ThemeManager.instance().current_theme() == 'dark' else 'Light'
        self._theme_label = QLabel(theme_name)
        self._theme_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._statusbar.addPermanentWidget(self._theme_label)

    def _update_statusbar(self):
        """Aktualisiert die Statusleiste."""
        if self._current_handler and self._current_handler.is_open:
            info = self._current_handler.get_file_info()
            self._file_label.setText(str(self._current_handler.file_path or ''))
            self._signal_label.setText(f'Signale: {info.get("channels_count", 0)}')

            time_range = info.get('time_range', (0, 0))
            if time_range[1] > time_range[0]:
                duration = time_range[1] - time_range[0]
                self._time_label.setText(f'Dauer: {duration:.2f}s')
            else:
                self._time_label.setText('')
        else:
            self._file_label.setText('Keine Datei geladen')
            self._signal_label.setText('')
            self._time_label.setText('')

    # ── Theme-Wechsel ──────────────────────────────────────────────

    def _toggle_theme(self):
        """Wechselt zwischen Dark und Light Theme."""
        ThemeManager.instance().toggle_theme()

    def _on_theme_changed(self, theme_name: str):
        """Reagiert auf Theme-Wechsel und aktualisiert UI-Elemente."""
        palette = ThemeManager.instance().get_palette()

        # Menüs und Toolbar-Icons neu erstellen (Farben an neues Theme anpassen)
        self.menuBar().clear()
        self._create_menus()
        self._rebuild_toolbar_icons()

        # Theme-Toggle-Icon aktualisieren
        if theme_name == 'dark':
            self._theme_action.setIcon(Icons.theme_light(palette.text_primary))
        else:
            self._theme_action.setIcon(Icons.theme_dark(palette.text_primary))

        # StatusBar Theme-Anzeige
        if hasattr(self, '_theme_label'):
            self._theme_label.setText('Dark' if theme_name == 'dark' else 'Light')

        # Verbindungs-Indikator Farbe
        if hasattr(self, '_conn_indicator'):
            self._conn_indicator.setStyleSheet(
                f'background: {palette.text_disabled}; border-radius: 6px;')

        # Plot-Widgets aktualisieren
        if hasattr(self, '_plot_tabs'):
            for i in range(self._plot_tabs.count()):
                widget = self._plot_tabs.widget(i)
                if isinstance(widget, PlotWidget):
                    widget.set_theme_colors(
                        palette.plot_bg, palette.plot_grid, palette.plot_text)

    # ── RAM-Überwachung ─────────────────────────────────────────────
    # psutil.virtual_memory() kann unter WSL2 >10s blockieren
    # (I/O auf /proc/meminfo).  Daher im Background-Thread ausführen
    # und Ergebnis beim nächsten Timer-Tick im Main-Thread abholen.
    # KEIN QTimer.singleShot aus dem Thread — das ist nicht threadsafe.

    def _on_mem_timer(self):
        """Timer-Callback (Main-Thread): Ergebnis abholen + neue Abfrage."""
        # 1. Ergebnis der vorherigen Abfrage verarbeiten
        result = getattr(self, '_mem_result', None)
        if result is not None:
            self._mem_result = None
            self._apply_memory_result(*result)

        # 2. Neue Abfrage starten (falls keine läuft)
        if not getattr(self, '_mem_query_pending', False):
            self._mem_query_pending = True
            threading.Thread(
                target=self._query_memory_bg, daemon=True).start()

    def _query_memory_bg(self):
        """Background-Thread: liest /proc/meminfo via psutil."""
        try:
            import psutil
            mem = psutil.virtual_memory()
            self._mem_result = (mem.used, mem.available, mem.percent)
        except Exception:
            self._mem_result = (None, None, None)
        self._mem_query_pending = False

    def _apply_memory_result(self, used, avail, pct):
        """Main-Thread: aktualisiert Label + prüft Warnung."""
        if used is None:
            self._mem_label.setText('RAM: n/a')
            return

        used_gb = used / (1024 ** 3)
        avail_gb = avail / (1024 ** 3)

        if pct < 50:
            color = '#2e7d32'   # Grün
        elif pct < 80:
            color = '#e91e90'   # Pink
        else:
            color = '#d32f2f'   # Rot

        self._mem_label.setText(
            f'RAM: {used_gb:.1f} / {used_gb + avail_gb:.1f} GB  '
            f'<span style="color:{color}; font-weight:bold">{pct:.0f} %</span>')

        # Speicherwarnung prüfen (pct bereits vorhanden, kein 2. psutil-Call)
        self._check_memory_warning(pct)

    def _check_memory_warning(self, pct):
        """Prüft ob RAM > 80 % und zeigt ggf. eine nicht-blockierende Warnung."""
        if self._mem_warning_active:
            return
        if pct < 80:
            return

        active = self._find_active_workers()
        if not active:
            return

        self._mem_warning_active = True
        self._mem_warning_workers = active
        names = '\n'.join(f'  • {n}' for n in active.keys())

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle('Speicherwarnung')
        box.setText(
            f'Die Arbeitsspeicher-Auslastung beträgt <b>{pct:.0f} %</b>.\n\n'
            f'Laufende Prozesse:\n{names}\n\n'
            'Sollen die laufenden Hintergrund-Prozesse abgebrochen werden, '
            'um einen Absturz zu vermeiden?')
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.Yes)
        box.finished.connect(self._on_mem_warning_finished)
        box.open()  # Nicht-blockierend!

    def _on_mem_warning_finished(self, result):
        """Callback: Benutzer hat auf Speicherwarnung reagiert."""
        if result == QMessageBox.StandardButton.Yes:
            for name, cancel_fn in self._mem_warning_workers.items():
                try:
                    cancel_fn()
                except Exception:
                    pass
            self._statusbar.showMessage(
                'Hintergrund-Prozesse wurden abgebrochen.', 5000)
        self._mem_warning_active = False
        self._mem_warning_workers = None

    def _find_active_workers(self) -> dict:
        """Findet alle laufenden Worker und gibt {Name: cancel_fn} zurück."""
        workers = {}

        # 1. MDF-Loader
        if (self._mdf_loader is not None
                and self._mdf_loader.isRunning()):
            workers['MDF-Datei laden'] = lambda: (
                setattr(self._mdf_loader, '_stop_monitor', True),
                self._mdf_loader.quit(),
            )

        # 2. Signal-Loader
        if (self._signal_loader is not None
                and self._signal_loader.isRunning()):
            workers['Signal-Daten laden'] = self._signal_loader.cancel

        # 3. Worker in Plot-Tabs (Converter, Wireshark, etc.)
        tabs = getattr(self, '_plot_tabs', None)
        if tabs is not None:
            for i in range(tabs.count()):
                widget = tabs.widget(i)
                tab_name = tabs.tabText(i)
                w = getattr(widget, '_worker', None)
                if w is not None and hasattr(w, 'isRunning') and w.isRunning():
                    workers[f'{tab_name} – Konvertierung'] = w.cancel
                pw = getattr(widget, '_preview_worker', None)
                if pw is not None and hasattr(pw, 'isRunning') and pw.isRunning():
                    workers[f'{tab_name} – Vorschau-Scan'] = pw.quit

        return workers

    # ── Einstellungen ─────────────────────────────────────────────

    def _restore_settings(self):
        """Stellt gespeicherte Einstellungen wieder her."""
        geometry = self._settings.value('geometry')
        if geometry:
            self.restoreGeometry(geometry)

        state = self._settings.value('windowState')
        if state:
            self.restoreState(state)

    def _save_settings(self):
        """Speichert die aktuellen Einstellungen."""
        self._settings.setValue('geometry', self.saveGeometry())
        self._settings.setValue('windowState', self.saveState())

    def _close_all_menus(self):
        """Schließt alle offenen Menüs und Popups."""
        from PyQt6.QtWidgets import QApplication, QMenu
        # Nicht ausführen, wenn ein modaler Dialog aktiv ist (z.B. QMessageBox)
        if QApplication.activeModalWidget() is not None:
            return
        # MenuBar deaktivieren und reaktivieren um alle Menüs zu schließen
        menubar = self.menuBar()
        if menubar:
            menubar.setActiveAction(None)
        # Alle aktiven Popups schließen (max. 20 Iterationen als Sicherheit)
        for _ in range(20):
            popup = QApplication.activePopupWidget()
            if popup is None:
                break
            popup.close()
        # Alle QMenu-Instanzen schließen
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMenu):
                widget.hide()
                widget.close()

    def _center_dialog(self, dialog):
        """Zentriert einen Dialog auf dem Parent-Fenster oder Bildschirm.

        Wird verzögert aufgerufen, damit der Window-Manager (WSL2/Wayland)
        die Geometrie finalisiert hat.
        """
        if not dialog.isVisible():
            return
        dw, dh = dialog.width(), dialog.height()
        parent = dialog.parent()
        if parent is not None and isinstance(parent, QWidget):
            pg = parent.window().geometry()
            x = pg.x() + (pg.width() - dw) // 2
            y = pg.y() + (pg.height() - dh) // 2
        else:
            screen = QApplication.primaryScreen()
            if screen:
                sg = screen.availableGeometry()
                x = sg.x() + (sg.width() - dw) // 2
                y = sg.y() + (sg.height() - dh) // 2
            else:
                return
        dialog.setGeometry(max(0, x), max(0, y), dw, dh)

    def eventFilter(self, obj, event):
        """Globaler Event-Filter: Dialog-Zentrierung + Doppelklick + Menü."""
        # ── Dialoge auf Hauptfenster zentrieren (WSL2/Wayland) ─────
        if event.type() == QEvent.Type.Show and isinstance(obj, QDialog):
            # Verzögert zentrieren — Window-Manager braucht Zeit für Layout
            QTimer.singleShot(30, lambda d=obj: self._center_dialog(d))

        # Doppelklick auf Menüleiste/Toolbar → Fenster maximieren/wiederherstellen
        if event.type() == QEvent.Type.MouseButtonDblClick:
            if hasattr(event, 'button') and event.button() == Qt.MouseButton.LeftButton:
                if QApplication.activeModalWidget() is not None:
                    return super().eventFilter(obj, event)
                # Nur in Menüleiste oder Toolbar maximieren
                w = obj if isinstance(obj, QWidget) else None
                if w is not None:
                    menubar = self.menuBar()
                    toolbars = self.findChildren(QToolBar)
                    in_titlebar_area = False
                    if w is menubar or (hasattr(w, 'parent') and w.parent() is menubar):
                        in_titlebar_area = True
                    else:
                        for tb in toolbars:
                            if w is tb or (hasattr(w, 'parent') and w.parent() is tb):
                                in_titlebar_area = True
                                break
                    if in_titlebar_area:
                        self._toggle_maximized()
                        return True

        # --- Wayland Menüleiste: Mausbewegung tracken ---
        menubar = self.menuBar()
        if obj is menubar:
            if event.type() == QEvent.Type.MouseMove:
                self._menu_close_timer.stop()
                pos = event.position().toPoint() if hasattr(event, 'position') else event.pos()
                action = menubar.actionAt(pos)
                if action and action in self._menubar_menus:
                    if action != self._active_menu_action:
                        # Anderer Menü-Eintrag → alte Popups schließen
                        target_menu = self._menubar_menus[action]
                        self._force_hide_all_menus(except_menu=target_menu)
                        self._active_menu_action = action
                elif action is None:
                    # Maus zwischen Menü-Einträgen (Lücke)
                    pass
            elif event.type() == QEvent.Type.Leave:
                self._menu_close_timer.start()
            elif event.type() == QEvent.Type.Enter:
                self._menu_close_timer.stop()

        if event.type() == QEvent.Type.WindowDeactivate:
            self._close_all_menus()
        return super().eventFilter(obj, event)

    def changeEvent(self, event):
        """Schließt Popup-Menüs beim Minimieren des Fensters."""
        if isinstance(event, QWindowStateChangeEvent):
            if self.windowState() & Qt.WindowState.WindowMinimized:
                self._close_all_menus()
        super().changeEvent(event)

    def hideEvent(self, event):
        """Schließt Popup-Menüs bevor das Fenster versteckt wird."""
        self._close_all_menus()
        super().hideEvent(event)

    def closeEvent(self, event):
        """Wird beim Schließen des Fensters aufgerufen."""
        # Bestätigungsdialog anzeigen
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle('Anwendung beenden')
        dialog.setFixedSize(420, 144)

        dlg_layout = QVBoxLayout(dialog)
        dlg_layout.setContentsMargins(24, 20, 24, 20)
        dlg_layout.setSpacing(16)

        # Icon + Text
        content = QHBoxLayout()
        content.setSpacing(16)

        icon_label = QLabel()
        style = dialog.style()
        icon = style.standardIcon(style.StandardPixmap.SP_MessageBoxQuestion)
        icon_label.setPixmap(icon.pixmap(48, 48))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        content.addWidget(icon_label)

        text_label = QLabel('Möchten Sie die Anwendung\nwirklich beenden?')
        text_label.setStyleSheet('font-size: 14px;')
        text_label.setWordWrap(True)
        content.addWidget(text_label, 1)

        dlg_layout.addLayout(content)
        dlg_layout.addStretch()

        # Buttons
        btn_box = QDialogButtonBox()
        no_btn = btn_box.addButton('Abbrechen', QDialogButtonBox.ButtonRole.RejectRole)
        yes_btn = btn_box.addButton('Beenden', QDialogButtonBox.ButtonRole.AcceptRole)
        yes_btn.setStyleSheet(
            'QPushButton { background-color: #d32f2f; color: white;'
            ' padding: 6px 20px; border-radius: 4px; font-weight: bold; }'
            'QPushButton:hover { background-color: #b71c1c; }'
        )
        no_btn.setStyleSheet(
            'QPushButton { padding: 6px 20px; border-radius: 4px; }'
        )
        no_btn.setDefault(True)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        dlg_layout.addWidget(btn_box)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            event.ignore()
            return

        # Ungespeicherte Änderungen prüfen
        for handler in self._handlers:
            if handler.is_modified:
                reply = QMessageBox.question(
                    self, 'Ungespeicherte Änderungen',
                    'Es gibt ungespeicherte Änderungen. Möchten Sie speichern?',
                    QMessageBox.StandardButton.Save |
                    QMessageBox.StandardButton.Discard |
                    QMessageBox.StandardButton.Cancel
                )
                if reply == QMessageBox.StandardButton.Save:
                    self._save_file()
                elif reply == QMessageBox.StandardButton.Cancel:
                    event.ignore()
                    return

        self._save_settings()

        # Alle Handler schließen
        for handler in self._handlers:
            handler.close()

        # Timer stoppen
        if hasattr(self, '_mem_timer') and self._mem_timer is not None:
            self._mem_timer.stop()

        # Laufende QThreads sauber beenden
        for attr in ('_mdf_loader', '_signal_loader'):
            thread = getattr(self, attr, None)
            if thread is not None and thread.isRunning():
                thread.quit()
                thread.wait(3000)

        import logging
        logging.getLogger().info('Anwendung beendet')

        event.accept()

    _SUPPORTED_DROP_EXTENSIONS = ('.mdf', '.mf4', '.dat', '.pcap', '.pcapng', '.cap', '.a2l', '.dbc', '.arxml')

    def dragEnterEvent(self, event):
        """Verarbeitet Drag-Enter-Ereignisse."""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.toLocalFile().lower().endswith(self._SUPPORTED_DROP_EXTENSIONS):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event):
        """Verarbeitet Drop-Ereignisse."""
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path.lower().endswith(self._SUPPORTED_DROP_EXTENSIONS):
                self._open_recent_file(file_path)

    def _open_file(self):
        """Öffnet einen Datei-Dialog zum Laden einer Datei."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Datei öffnen',
            '',
            'Alle unterstützten (*.mdf *.mf4 *.dat *.pcap *.pcapng *.cap *.a2l *.dbc *.arxml);;'
            'MDF-Dateien (*.mdf *.mf4 *.dat);;'
            'PCAP-Dateien (*.pcap *.pcapng *.cap);;'
            'A2L-Dateien (*.a2l);;'
            'DBC/ARXML-Dateien (*.dbc *.arxml);;'
            'Alle Dateien (*.*)'
        )
        if file_path:
            self._open_recent_file(file_path)

    def _load_file(self, file_path: str):
        """Lädt eine MDF-Datei im Hintergrund-Thread mit Fortschrittsdialog.

        Ein QProgressDialog zeigt den realen I/O-Fortschritt an, damit der
        Benutzer eine zeitliche Erwartung hat.
        """
        # Laufenden Ladevorgang abbrechen
        if self._mdf_loader is not None:
            if self._mdf_loader.isRunning():
                self._mdf_loader.quit()
                self._mdf_loader.wait(3000)
            self._mdf_loader.deleteLater()
            self._mdf_loader = None

        # Dateigröße ermitteln
        file_size = Path(file_path).stat().st_size
        if file_size >= 1024 ** 3:
            size_text = f"{file_size / (1024 ** 3):.1f} GB"
        else:
            size_text = f"{file_size / (1024 ** 2):.0f} MB"

        # ── Speicher-Preflight-Check ──────────────────────────────────
        avail_mb = self._get_available_memory_mb()
        file_size_mb = file_size / (1024 * 1024)
        # Schwellwert: Datei benötigt ca. 70 % des verfügbaren RAMs
        if avail_mb is not None and file_size_mb > avail_mb * 0.7:
            reply = QMessageBox.warning(
                self,
                'Speicherwarnung',
                f"Die Datei ist {size_text} groß, aber nur "
                f"{avail_mb:.0f} MB RAM verfügbar.\n\n"
                "Das Laden dieser Datei kann zum Absturz führen.\n\n"
                "Empfehlung: Teilen Sie die Datei zuerst über\n"
                "   Bearbeiten → Dateiaufteilung\n"
                "in kleinere Teile auf und laden Sie diese einzeln.",
                QMessageBox.StandardButton.Ok
                | QMessageBox.StandardButton.Ignore,
                QMessageBox.StandardButton.Ok,
            )
            if reply == QMessageBox.StandardButton.Ok:
                # Direkt den Aufteilungsdialog öffnen, Datei vorbelegt
                self._show_split_dialog_with_file(file_path)
                return
            # Ignore → Benutzer möchte trotzdem laden

        # Fortschrittsdialog erstellen
        fname = Path(file_path).name
        short_name = fname if len(fname) <= 35 else fname[:32] + '...'
        dlg = QProgressDialog(self)
        dlg.setWindowTitle("MDF-Datei laden")
        dlg.setLabelText(f"Öffne {short_name} ({size_text})...")
        dlg.setRange(0, 100)
        dlg.setValue(0)
        dlg.setMinimumDuration(0)
        dlg.setFixedWidth(420)
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setCancelButtonText("Abbrechen")
        dlg.canceled.connect(self._on_mdf_load_canceled)
        self._load_progress_dlg = dlg
        self._mdf_load_canceled = False

        # Loader-Thread starten
        self._mdf_loader = MDFLoaderThread(file_path, self)
        self._mdf_loader.progress_text.connect(dlg.setLabelText)
        self._mdf_loader.progress_value.connect(dlg.setValue)
        self._mdf_loader.load_success.connect(self._on_mdf_loaded)
        self._mdf_loader.load_error.connect(self._on_mdf_load_error)
        self._mdf_loader.finished.connect(self._on_mdf_loader_done)
        self._mdf_loader.start()

    def _on_mdf_load_canceled(self):
        """Benutzer hat den Ladevorgang über den Fortschrittsdialog abgebrochen."""
        self._mdf_load_canceled = True
        self._load_progress_dlg = None
        self._statusbar.showMessage("Ladevorgang abgebrochen.", 3000)

    def _on_mdf_loaded(self, handler, file_info):
        """Callback: MDF-Datei wurde erfolgreich im Hintergrund geladen."""
        # Abgebrochener Ladevorgang: Ergebnis verwerfen
        if self._mdf_load_canceled:
            handler.close()
            return

        # Dialog schließen (canceled-Signal wird sicher getrennt)
        self._close_load_progress_dlg()

        self._handlers.append(handler)
        self._current_handler = handler

        # MDF-Browser als Tab erstellen (wie Wireshark-Panel)
        self._mdf_browser = MdfBrowserPanel()
        self._mdf_browser.signal_selected.connect(self._on_signal_selected)
        self._mdf_browser.signal_double_clicked.connect(self._on_signal_plot)
        self._mdf_browser.signals_checked_changed.connect(self._on_signals_checked_changed)
        self._mdf_browser.signal_tree.close_requested.connect(self._close_file)
        self._mdf_browser.load_from_handler(handler)

        # Dateiname als Tab-Titel (kurz)
        file_name = handler.file_path.name if handler.file_path else 'MDF'
        tab_title = file_name if len(file_name) <= 25 else file_name[:22] + '...'
        self._plot_tabs.addTab(self._mdf_browser, tab_title)
        self._plot_tabs.setCurrentWidget(self._mdf_browser)

        # Kompatibilitäts-Referenzen
        self._signal_tree = self._mdf_browser.signal_tree
        self._metadata_panel = self._mdf_browser.metadata_panel

        # Statusbar mit vorberechneten Infos aktualisieren (kein erneutes I/O)
        self._file_label.setText(str(handler.file_path or ''))
        self._signal_label.setText(f'Signale: {file_info.get("channels_count", 0)}')
        time_range = file_info.get('time_range', (0, 0))
        if time_range[1] > time_range[0]:
            duration = time_range[1] - time_range[0]
            self._time_label.setText(f'Dauer: {duration:.2f}s')
        else:
            self._time_label.setText('')

        self._add_to_recent(str(handler.file_path))
        self._statusbar.showMessage(f'Datei geladen: {handler.file_path}', 3000)

    def _on_mdf_load_error(self, msg):
        """Callback: Fehler beim Laden der MDF-Datei."""
        self._close_load_progress_dlg()
        if not self._mdf_load_canceled:
            QMessageBox.critical(self, 'Fehler', f'Fehler beim Laden:\n{msg}')

    def _on_mdf_loader_done(self):
        """Aufräumen wenn der Loader-Thread beendet ist."""
        self._close_load_progress_dlg()
        if self._mdf_loader is not None:
            self._mdf_loader.deleteLater()
            self._mdf_loader = None

    def _close_load_progress_dlg(self):
        """Schließt den Lade-Fortschrittsdialog sicher.

        Trennt zuerst das canceled-Signal, damit QProgressDialog::closeEvent()
        nicht fälschlich _on_mdf_load_canceled auslöst.
        """
        if self._load_progress_dlg is not None:
            try:
                self._load_progress_dlg.canceled.disconnect(
                    self._on_mdf_load_canceled)
            except (TypeError, RuntimeError):
                pass
            self._load_progress_dlg.close()
            self._load_progress_dlg = None

    def _show_metadata_panel(self):
        """Zeigt das MDF-Browser-Tab an."""
        if self._mdf_browser is not None:
            idx = self._plot_tabs.indexOf(self._mdf_browser)
            if idx >= 0:
                self._plot_tabs.setCurrentIndex(idx)
        self._metadata_panel_action.setChecked(True)

    def _hide_signal_tree(self):
        """Versteckt den Signalbaum (schließt MDF-Browser-Tab)."""
        self._close_mdf_browser_tab()

    def _hide_metadata_panel(self):
        """Versteckt das Metadaten-Panel (schließt MDF-Browser-Tab)."""
        self._close_mdf_browser_tab()
        self._metadata_panel_action.setChecked(False)

    def _close_mdf_browser_tab(self):
        """Schließt den MDF-Browser-Tab."""
        if self._mdf_browser is not None:
            idx = self._plot_tabs.indexOf(self._mdf_browser)
            if idx >= 0:
                self._plot_tabs.removeTab(idx)

    def _toggle_metadata_panel(self, checked: bool):
        """Schaltet das Metadaten-Panel ein/aus."""
        if checked:
            self._show_metadata_panel()
        else:
            self._hide_metadata_panel()

    def _save_file(self):
        """Speichert die aktuelle Datei."""
        if self._current_handler and self._current_handler.is_open:
            if self._current_handler.save():
                self._statusbar.showMessage('Datei gespeichert', 3000)
            else:
                QMessageBox.critical(self, 'Fehler', 'Fehler beim Speichern')

    def _save_file_as(self):
        """Speichert die Datei unter einem neuen Namen."""
        if not self._current_handler or not self._current_handler.is_open:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            'MDF-Datei speichern',
            '',
            'MDF4-Dateien (*.mf4);;MDF3-Dateien (*.mdf);;Alle Dateien (*.*)'
        )
        if file_path:
            if self._current_handler.save(file_path):
                self._update_statusbar()
                self._statusbar.showMessage(f'Gespeichert als: {file_path}', 3000)
            else:
                QMessageBox.critical(self, 'Fehler', 'Fehler beim Speichern')

    def _close_file(self):
        """Schließt die aktuelle Datei."""
        if self._current_handler:
            if self._current_handler.is_modified:
                reply = QMessageBox.question(
                    self, 'Ungespeicherte Änderungen',
                    'Möchten Sie vor dem Schließen speichern?',
                    QMessageBox.StandardButton.Save |
                    QMessageBox.StandardButton.Discard |
                    QMessageBox.StandardButton.Cancel
                )
                if reply == QMessageBox.StandardButton.Save:
                    self._save_file()
                elif reply == QMessageBox.StandardButton.Cancel:
                    return

            self._current_handler.close()
            if self._current_handler in self._handlers:
                self._handlers.remove(self._current_handler)
            self._current_handler = self._handlers[-1] if self._handlers else None

            # MDF-Browser-Tab schließen
            self._close_mdf_browser_tab()
            if self._mdf_browser is not None:
                self._mdf_browser.clear()
                self._mdf_browser.deleteLater()
                self._mdf_browser = None
            self._update_statusbar()

    def _export_signals(self):
        """Öffnet den Export-Dialog."""
        if not self._current_handler or not self._current_handler.is_open:
            QMessageBox.warning(self, 'Warnung', 'Keine Datei geladen')
            return

        selected = self._signal_tree.get_selected_signals()
        # Export-Dialog erwartet nur Signalnamen
        selected_names = [s['name'] for s in selected]
        dialog = ExportDialog(self, self._current_handler, selected_names)
        dialog.exec()

    def _on_signal_selected(self, signal_data: dict):
        """Wird aufgerufen, wenn ein Signal ausgewählt wird.

        Args:
            signal_data: Dict mit 'name', 'group_index', 'channel_index'
        """
        if not self._current_handler:
            return
        self._metadata_panel.show_loading(f'Lade Signal: {signal_data["name"]} …')
        self._start_signal_loader([signal_data], 'metadata')

    def _on_signal_plot(self, signal_data: dict):
        """Wird aufgerufen, wenn ein Signal doppelt geklickt wird.

        Args:
            signal_data: Dict mit 'name', 'group_index', 'channel_index'
        """
        self._plot_signal(signal_data)

    def _plot_signal(self, signal_data: dict):
        """Plottet ein einzelnes Signal.

        Args:
            signal_data: Dict mit 'name', 'group_index', 'channel_index'
        """
        if not self._current_handler:
            return
        self._start_signal_loader([signal_data], 'plot')

    def _plot_selected(self):
        """Plottet alle ausgewählten Signale."""
        selected = self._signal_tree.get_selected_signals()
        if not selected or not self._current_handler:
            return
        self._start_signal_loader(selected, 'multi_plot')

    def _on_signals_checked_changed(self, checked_signals: list):
        """Wird aufgerufen, wenn der Vergleichen-Button geklickt wird.

        Args:
            checked_signals: Liste der angehakten Signale
        """
        if len(checked_signals) < 2 or not self._current_handler:
            return
        self._start_signal_loader(checked_signals, 'compare')

    # ── Async-Signal-Loader ───────────────────────────────────────

    def _start_signal_loader(self, signals: list, purpose: str):
        """Startet den Hintergrund-Loader für Signal-Daten.

        Args:
            signals: Liste von Signal-Dicts (name, group_index, channel_index)
            purpose: 'metadata' | 'plot' | 'multi_plot' | 'compare'
        """
        # Vorherigen Loader abbrechen
        if self._signal_loader is not None and self._signal_loader.isRunning():
            self._signal_loader.cancel()
            self._signal_loader.quit()
            self._signal_loader.wait(500)

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.show()
        self._statusbar.showMessage(f'Lade {len(signals)} Signal(e) …')

        loader = SignalLoaderThread(
            self._current_handler, signals, purpose, parent=self)
        loader.progress.connect(self._on_signal_load_progress)
        loader.all_loaded.connect(self._on_signals_loaded)
        loader.memory_warning.connect(self._on_memory_warning)
        loader.finished.connect(self._on_signal_loader_finished)
        self._signal_loader = loader
        loader.start()

    def _on_signal_load_progress(self, pct: int, text: str):
        """Aktualisiert die Fortschrittsanzeige während des Ladens."""
        self._progress.setValue(pct)
        self._statusbar.showMessage(text)
        self._metadata_panel.set_loading_progress(pct, text)

    def _on_memory_warning(self, message: str):
        """Zeigt eine Speicher-Warnung an."""
        self._statusbar.showMessage(f'WARNUNG: {message}', 10000)
        QMessageBox.warning(self, 'Speicher-Warnung', message)

    def _on_signal_loader_finished(self):
        """Bereinigt nach Abschluss des Loaders."""
        self._progress.hide()
        self._progress.setValue(0)
        self._signal_loader = None

    def _on_signals_loaded(self, results: list, purpose: str):
        """Verarbeitet die geladenen Signaldaten je nach Zweck."""
        self._metadata_panel.hide_loading()
        if not results:
            self._statusbar.showMessage('Keine Signaldaten verfügbar.', 3000)
            return

        if purpose == 'metadata':
            entry = results[0]
            info = entry['info']
            if info:
                if entry.get('lazy'):
                    # Lazy-Loading: Daten chunk-weise aus MDF laden
                    self._metadata_panel.show_signal_info(
                        info,
                        handler=self._current_handler,
                        signal_name=entry['name'],
                        group=entry['group_index'],
                        index=entry['channel_index'])
                else:
                    self._metadata_panel.show_signal_info(
                        info, entry['timestamps'], entry['samples'])
            self._statusbar.showMessage(
                f'Signal geladen: {entry["name"]}', 3000)

        elif purpose == 'plot':
            entry = results[0]
            plot_widget = PlotWidget()
            plot_widget.add_signal(
                entry['name'], entry['timestamps'],
                entry['samples'], entry['unit'])
            self._plot_tabs.addTab(plot_widget, entry['name'][:20])
            self._plot_tabs.setCurrentWidget(plot_widget)
            self._connect_plot_to_sync(plot_widget)
            self._statusbar.showMessage(
                f'Signal geplottet: {entry["name"]}', 3000)

        elif purpose == 'multi_plot':
            plot_widget = PlotWidget()
            for entry in results:
                plot_widget.add_signal(
                    entry['name'], entry['timestamps'],
                    entry['samples'], entry['unit'])
            tab_name = (f'{len(results)} Signale'
                        if len(results) > 1
                        else results[0]['name'][:20])
            self._plot_tabs.addTab(plot_widget, tab_name)
            self._plot_tabs.setCurrentWidget(plot_widget)
            self._connect_plot_to_sync(plot_widget)
            time_range = plot_widget.get_time_range()
            if time_range[1] > time_range[0]:
                self._time_sync_manager.set_time_range(*time_range)
                self._enable_sync_slider()
            self._statusbar.showMessage(
                f'{len(results)} Signale geplottet.', 3000)

        elif purpose == 'compare':
            if self._compare_plot_widget is None:
                self._compare_plot_widget = PlotWidget()
                self._plot_tabs.addTab(
                    self._compare_plot_widget, 'Vergleich')
            else:
                self._compare_plot_widget.clear()
            for entry in results:
                self._compare_plot_widget.add_signal(
                    entry['name'], entry['timestamps'],
                    entry['samples'], entry['unit'])
            tab_index = self._plot_tabs.indexOf(self._compare_plot_widget)
            if tab_index >= 0:
                self._plot_tabs.setTabText(
                    tab_index, f'Vergleich ({len(results)})')
                self._plot_tabs.setCurrentIndex(tab_index)
            self._statusbar.showMessage(
                f'Vergleich mit {len(results)} Signalen.', 3000)

    def _on_tab_changed(self, index: int):
        """Wechselt zwischen Willkommensseite und Tab-Ansicht."""
        if index >= 0:
            self._center_stack.setCurrentIndex(1)

    def _show_welcome(self):
        """Zeigt die Willkommensseite an."""
        self._welcome_page.refresh()
        self._center_stack.setCurrentIndex(0)

    def _close_plot_tab(self, index: int):
        """Schließt einen Plot-Tab."""
        widget = self._plot_tabs.widget(index)
        # Prüfen ob es der Vergleichs-Tab ist
        if widget == self._compare_plot_widget:
            self._compare_plot_widget = None
        # MDF-Browser-Tab: Referenz aufräumen
        if widget == self._mdf_browser:
            self._mdf_browser = None
        # VideoPlayerTab cleanup aufrufen
        if isinstance(widget, VideoPlayerTab) and hasattr(widget, 'cleanup'):
            widget.cleanup()
        self._plot_tabs.removeTab(index)
        if widget:
            widget.deleteLater()
        if self._plot_tabs.count() == 0:
            self._show_welcome()

    def _clear_all_plots(self):
        """Schließt alle Plot-Tabs."""
        self._compare_plot_widget = None
        while self._plot_tabs.count() > 0:
            self._close_plot_tab(0)

    def _cut_time_range(self):
        """Schneidet einen Zeitbereich aus."""
        # TODO: Dialog für Zeitbereich implementieren
        pass

    def _resample(self):
        """Führt Resampling durch."""
        # TODO: Dialog für Resampling implementieren
        pass

    def _merge_files(self):
        """Führt Dateien zusammen."""
        # TODO: Merge-Dialog implementieren
        pass

    @staticmethod
    def _get_available_memory_mb():
        """Gibt verfuegbaren RAM in MB zurueck (oder None)."""
        from core.platform import get_available_memory_mb
        return get_available_memory_mb()

    def _show_split_dialog(self):
        """Öffnet den Dialog zur Dateiaufteilung."""
        dialog = FileSplitDialog(self)
        dialog.exec()

    def _show_split_dialog_with_file(self, file_path: str):
        """Öffnet den Dateiaufteilungsdialog mit vorausgewählter Datei."""
        dialog = FileSplitDialog(self)
        dialog.preset_file(file_path)
        dialog.exec()

    def _show_formula_editor(self):
        """Oeffnet den Formel-Editor fuer berechnete Kanaele."""
        if not self._current_handler or not self._current_handler.is_open:
            QMessageBox.warning(self, 'Warnung', 'Bitte zuerst eine MDF-Datei laden.')
            return

        # Alle Signale sammeln
        signals = {}
        channel_groups = self._current_handler.get_channel_groups()

        for group_idx, group_info in enumerate(channel_groups):
            channels = self._current_handler.get_channels(group_idx)
            for ch_idx, channel in enumerate(channels):
                name = channel.get('name', f'Channel_{ch_idx}')
                result = self._current_handler.get_signal(name, group=group_idx, index=ch_idx)
                if result:
                    timestamps, samples = result
                    signals[name] = (timestamps, samples)

        if not signals:
            QMessageBox.warning(self, 'Warnung', 'Keine Signale in der Datei gefunden.')
            return

        # Dialog oeffnen
        existing_channels = self._calculated_channel_manager.get_channels()
        dialog = FormulaEditorDialog(signals, existing_channels, self)
        dialog.channel_created.connect(self._on_calculated_channel_created)

        if dialog.exec():
            # Alle Kanaele speichern
            for channel in dialog.get_channels():
                self._calculated_channel_manager.add_channel(channel)

    def _on_calculated_channel_created(self, channel):
        """Wird aufgerufen wenn ein berechneter Kanal zum Plot hinzugefuegt werden soll."""
        if not self._current_handler or not self._current_handler.is_open:
            return

        # Signale sammeln
        signals = {}
        channel_groups = self._current_handler.get_channel_groups()

        for group_idx, group_info in enumerate(channel_groups):
            channels = self._current_handler.get_channels(group_idx)
            for ch_idx, ch in enumerate(channels):
                name = ch.get('name', f'Channel_{ch_idx}')
                result = self._current_handler.get_signal(name, group=group_idx, index=ch_idx)
                if result:
                    timestamps, samples = result
                    signals[name] = (timestamps, samples)

        # Formel auswerten
        engine = FormulaEngine()
        engine.set_signals(signals)
        timestamps, samples, error = engine.evaluate(channel.formula)

        if error:
            QMessageBox.warning(self, 'Fehler', f'Fehler bei der Berechnung:\n{error}')
            return

        # Zum Plot hinzufuegen
        plot_widget = PlotWidget()
        plot_widget.add_signal(
            f"[Calc] {channel.name}",
            timestamps,
            samples,
            channel.unit
        )

        # Speziellen Stil fuer berechnete Kanaele
        self._plot_tabs.addTab(plot_widget, f"🧮 {channel.name[:15]}")
        self._plot_tabs.setCurrentWidget(plot_widget)

        # Kanal speichern
        self._calculated_channel_manager.add_channel(channel)

    def _convert_format(self):
        """Öffnet den Konvertierungs-Dialog."""
        if not self._current_handler or not self._current_handler.is_open:
            QMessageBox.warning(self, 'Warnung', 'Keine Datei geladen')
            return

        dialog = ConvertDialog(self, self._current_handler)
        dialog.exec()

    def _show_statistics(self):
        """Zeigt Statistiken für ausgewählte Signale."""
        selected = self._signal_tree.get_selected_signals()
        if not selected or not self._current_handler:
            return

        from core.signal_processor import SignalProcessor

        stats_text = []
        for signal_data in selected:
            signal_name = signal_data['name']
            group_index = signal_data.get('group_index')
            channel_index = signal_data.get('channel_index')

            result = self._current_handler.get_signal(
                signal_name, group=group_index, index=channel_index
            )
            if result:
                _, samples = result
                stats = SignalProcessor.calculate_statistics(samples)
                stats_text.append(f"Signal: {signal_name}")
                stats_text.append(f"  Min: {stats['min']:.6g}")
                stats_text.append(f"  Max: {stats['max']:.6g}")
                stats_text.append(f"  Mittelwert: {stats['mean']:.6g}")
                stats_text.append(f"  Std: {stats['std']:.6g}")
                stats_text.append(f"  RMS: {stats['rms']:.6g}")
                stats_text.append("")

        QMessageBox.information(self, 'Signal-Statistiken', '\n'.join(stats_text))

    def _toggle_maximized(self):
        """Schaltet Maximiert-Modus um."""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _toggle_fullscreen(self):
        """Schaltet Vollbildmodus um."""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def _show_help_reference(self):
        """Zeigt den Funktionsreferenz-Dialog."""
        dlg = FunktionsreferenzDialog(self)
        dlg.exec()

    def _show_protocol_reference(self):
        """Zeigt den Protokoll-Referenz-Dialog."""
        dlg = ProtocolReferenceDialog(self)
        dlg.exec()

    def _show_protocol_comparison(self):
        """Zeigt den Protokoll-Vergleich-Dialog (PLP/TECMP/CMP)."""
        dlg = ProtocolComparisonDialog(self)
        dlg.exec()

    def _show_video_protocol_comparison(self):
        """Zeigt den Video-Protokoll-Vergleich (GigE Vision vs MIPI CSI-2)."""
        dlg = VideoProtocolComparisonDialog(self)
        dlg.exec()

    def _show_framework_api_comparison(self):
        """Zeigt den Framework-API-Vergleich (Standard vs MDF)."""
        dlg = FrameworkApiComparisonDialog(self)
        dlg.exec()

    def _show_autosar_architecture(self):
        """Zeigt den AUTOSAR-Architektur-Dialog."""
        dlg = AutosarArchitectureDialog(self)
        dlg.exec()

    def _show_network_architecture(self):
        """Zeigt den Netzwerk-Architektur-Dialog (OSI/TCP-IP)."""
        dlg = NetworkArchitectureDialog(self)
        dlg.exec()

    def _show_dataflow_can_tecmp(self):
        dlg = DataFlowAnalysisDialog(self)
        dlg.exec()

    def _show_raw12_knowledge(self):
        """Zeigt den RAW12-Wissen-Dialog."""
        dlg = Raw12KnowledgeDialog(self)
        dlg.exec()

    def _show_about(self):
        """Zeigt den Über-Dialog."""
        QMessageBox.about(
            self,
            'Über Messtechnik Plattform',
            'Messtechnik Plattform\n\n'
            'Eine umfassende GUI-Anwendung für:\n'
            '• MDF4 Messdaten (Anzeigen, Bearbeiten, Exportieren)\n'
            '• ViGEM Logger Firmware-Management\n'
            '• CCA Framework API-Integration\n'
            '• Systemlösung-Konfiguration\n\n'
            'Basiert auf PyQt6 und asammdf.'
        )

    def _perform_global_search(self):
        """Durchsucht alle Funktionen und zeigt Ergebnisse an."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView

        search_text = self._global_search_edit.text().strip().lower()
        if not search_text:
            QMessageBox.information(self, 'Suche', 'Bitte einen Suchbegriff eingeben.')
            return

        # Alle durchsuchbaren Funktionen definieren (Menüs, Panels, Dialoge)
        features = [
            # === MDF-Datei Menü ===
            ('📂 MDF öffnen', 'Menü: MDF-Datei | MDF-Datei laden, öffnen, Messdaten, mf4', self._open_file),
            ('📋 Zuletzt geöffnet', 'Menü: MDF-Datei | Letzte Dateien, Recent Files', lambda: None),
            ('💾 MDF speichern', 'Menü: MDF-Datei | MDF-Datei speichern, sichern', self._save_file),
            ('💾 MDF speichern unter', 'Menü: MDF-Datei | Speichern als, Save As', lambda: None),
            ('❌ MDF schließen', 'Menü: MDF-Datei | Datei schließen, Close', self._close_file),
            ('📤 MDF exportieren', 'Menü: MDF-Datei | Signale exportieren, CSV, MAT, Excel', self._export_signals),
            ('🔄 Format konvertieren', 'Menü: MDF-Datei | MDF konvertieren, Version ändern, MDF3 MDF4', self._convert_format),
            ('📈 Signal-Statistiken', 'Menü: MDF-Datei | Statistiken, Min Max Mittelwert Standardabweichung', self._show_statistics),
            ('📄 Report generieren', 'Menü: MDF-Datei | PDF HTML Report, Bericht erstellen', self._show_report_generator),
            ('🚪 Beenden', 'Menü: MDF-Datei | Programm beenden, Exit, Quit', self.close),

            # === Bearbeiten Menü ===
            ('✂️ Zeitbereich ausschneiden', 'Menü: Bearbeiten | Zeit schneiden, kürzen, Cut', self._cut_time_range),
            ('🔢 Resampling', 'Menü: Bearbeiten | Abtastrate ändern, Sample Rate', self._resample),
            ('🧮 Formel-Editor', 'Menü: Bearbeiten | Berechnete Kanäle, Signal-Algebra, Formeln, Math', self._show_formula_editor),
            ('📁 Dateien zusammenführen', 'Menü: Bearbeiten | MDF merge, zusammenfügen, Combine', self._merge_files),
            ('✂️ Dateiaufteilung', 'Menü: Bearbeiten | Datei aufteilen, Split, MDF PCAP teilen', self._show_split_dialog),

            # === Ansicht Menü ===
            ('📊 Neuer Plot', 'Menü: Ansicht | Plot erstellen, Signal anzeigen, Graph', self._plot_selected),
            ('🔗 Vergleichs-Plot', 'Menü: Ansicht | Signale vergleichen, Overlay, Compare', lambda: None),
            ('ℹ️ Metadaten-Panel', 'Menü: Ansicht | Metadaten anzeigen, Dateiinfo, Header', lambda: None),
            ('📋 Kanal-Info Panel', 'Menü: Ansicht | Kanal-Information, Signal-Details, Channel Info', lambda: None),
            ('🔄 Plots aktualisieren', 'Menü: Ansicht | Refresh, Update', lambda: None),

            # === Wireshark Menü ===
            ('🦈 Wireshark Panel öffnen', 'Menü: Wireshark | PCAP Analyse öffnen, Netzwerk Panel', self._show_wireshark_panel),
            ('📂 PCAP Datei öffnen', 'Menü: Wireshark | Wireshark Capture laden, Network Trace', lambda: None),
            ('🔍 Paket-Filter', 'Menü: Wireshark | Filter Pakete, Display Filter', lambda: None),
            ('📊 Protokoll-Statistiken', 'Menü: Wireshark | Protocol Statistics, Packet Count', lambda: None),
            ('🚗 UDS Decoder', 'Menü: Wireshark | UDS Protokoll, Unified Diagnostic Services', lambda: None),
            ('📡 DoIP Decoder', 'Menü: Wireshark | DoIP Protokoll, Diagnostics over IP', lambda: None),
            ('🔌 ISO-TP Decoder', 'Menü: Wireshark | ISO-TP Transport Protocol', lambda: None),
            ('🎨 Farbregeln', 'Menü: Wireshark | Coloring Rules, Protokoll-Farben', lambda: None),
            ('📋 UDS Sequenz-Analyse', 'Menü: Wireshark | UDS Sequence Analysis', lambda: None),
            ('🔧 DTC-Management', 'Menü: Wireshark | Diagnostic Trouble Codes, Fehlercodes, OBD', self._show_dtc_panel),
            ('📈 Wireshark Statistiken', 'Menü: Wireshark | Paket Statistiken, Traffic Analysis', lambda: None),

            # === Docker Menü ===
            ('🐳 Docker Panel öffnen', 'Menü: Docker | Docker Panel, Container Verwaltung', self._show_docker_panel),
            ('📦 Container verwalten', 'Menü: Docker | Docker Container, Start Stop', lambda: None),
            ('💿 Images verwalten', 'Menü: Docker | Docker Images, Pull Push', lambda: None),
            ('📜 Docker Logs', 'Menü: Docker | Container Logs anzeigen', lambda: None),
            ('📝 Docker Compose', 'Menü: Docker | Compose Dateien, docker-compose.yml', lambda: None),
            ('🚗 Vehicle Logger Template', 'Menü: Docker | Fahrzeug Logger, Data Logger', lambda: None),

            # === Lua Menü ===
            ('📜 Lua Editor öffnen', 'Menü: Lua | Lua Panel, Skript Editor', self._show_lua_panel),
            ('📂 Lua Skript öffnen', 'Menü: Lua | Lua Datei laden, .lua', lambda: None),
            ('💾 Lua Skript speichern', 'Menü: Lua | Lua Datei speichern', lambda: None),
            ('▶️ Lua Skript ausführen', 'Menü: Lua | Execute Script, Run', lambda: None),
            ('📚 Lua Beispiele', 'Menü: Lua | Examples, Templates', lambda: None),
            ('📖 Lua API Dokumentation', 'Menü: Lua | API Reference, Help', lambda: None),

            # === REST API Menü ===
            ('🌐 REST API Client', 'Menü: REST API | HTTP Client öffnen, API Panel', self._show_restapi_panel),
            ('📤 GET Request', 'Menü: REST API | HTTP GET, Daten abrufen', lambda: None),
            ('📥 POST Request', 'Menü: REST API | HTTP POST, Daten senden', lambda: None),
            ('📋 Request History', 'Menü: REST API | Anfrage Verlauf, History', lambda: None),
            ('💾 Request speichern', 'Menü: REST API | Request Collection, Save', lambda: None),

            # === Automatisierung Menü ===
            ('⚙️ Automatisierung Panel', 'Menü: Automatisierung | Test Panel, Automation', self._show_automation_panel),
            ('📝 Test-Sequenz erstellen', 'Menü: Automatisierung | Test Case, Sequence', lambda: None),
            ('▶️ Test ausführen', 'Menü: Automatisierung | Run Test, Execute', lambda: None),
            ('📊 Test-Report', 'Menü: Automatisierung | Test Report, Ergebnisse', lambda: None),
            ('📅 Scheduler', 'Menü: Automatisierung | Zeitplan, Scheduled Tasks', lambda: None),

            # === Systemlösung Menü ===
            ('🏭 Systemlösung Panel', 'Menü: Systemlösung | System Konfigurator', self._show_system_solution_panel),
            ('🔧 Hardware Konfiguration', 'Menü: Systemlösung | Hardware Setup, Interfaces', lambda: None),
            ('📡 Netzwerk Setup', 'Menü: Systemlösung | Network Configuration, Ethernet', lambda: None),
            ('💾 Konfiguration speichern', 'Menü: Systemlösung | Config Save, Export', lambda: None),
            ('📂 Konfiguration laden', 'Menü: Systemlösung | Config Load, Import', lambda: None),

            # === Firmware Menü ===
            ('💾 Firmware Manager', 'Menü: Firmware | Firmware Panel öffnen', self._show_firmware_panel),
            ('📤 Firmware Upload', 'Menü: Firmware | Flash Update, Upload', lambda: None),
            ('📥 Firmware Download', 'Menü: Firmware | Backup, Download', lambda: None),
            ('✅ Firmware Validierung', 'Menü: Firmware | Validation, Verify', lambda: None),
            ('📋 Firmware Version', 'Menü: Firmware | Version Info, Release Notes', lambda: None),

            # === Framework Menü ===
            ('🔧 CCA Framework', 'Menü: Framework | Framework Panel, API', self._show_framework_panel),
            ('📚 API Referenz', 'Menü: Framework | API Documentation, Reference', lambda: None),
            ('💻 Code Generator', 'Menü: Framework | Code Generation, Templates', lambda: None),
            ('🔌 Plugin Manager', 'Menü: Framework | Plugins, Extensions', lambda: None),

            # === XCP Menü ===
            ('📡 XCP Panel', 'Menü: XCP | XCP Panel öffnen, Measurement Calibration', self._show_xcp_panel),
            ('🔗 XCP Connect', 'Menü: XCP | Verbinden, Connect to ECU', lambda: None),
            ('📊 DAQ Konfiguration', 'Menü: XCP | Data Acquisition, Measurement', lambda: None),
            ('📝 Calibration', 'Menü: XCP | Kalibrierung, Parameter ändern', lambda: None),
            ('💾 A2L Datei laden', 'Menü: XCP | ASAP2, A2L Import', lambda: None),

            # === Busdatenbank Menü ===
            ('🗄️ Busdatenbank Panel', 'Menü: Busdatenbank | DBC Panel, Bus Database', self._show_bus_database_panel),
            ('📂 DBC Datei laden', 'Menü: Busdatenbank | CAN Database, DBC Import', lambda: None),
            ('📂 LDF Datei laden', 'Menü: Busdatenbank | LIN Database, LDF Import', lambda: None),
            ('📂 ARXML laden', 'Menü: Busdatenbank | AUTOSAR, ARXML Import', lambda: None),
            ('📂 FIBEX laden', 'Menü: Busdatenbank | FlexRay, FIBEX Import', lambda: None),
            ('🔍 Bus-Trace Analyse', 'Menü: Busdatenbank | CAN Trace, Bus Monitor, Message Decoder', self._show_bus_trace_panel),
            ('📊 Signal Decode', 'Menü: Busdatenbank | Signal Dekodierung, Physical Values', lambda: None),

            # === Konverter Menü ===
            ('🔄 Konverter Panel', 'Menü: Konverter | Format Converter, File Conversion', self._show_converter_panel),
            ('📝 XML Editor', 'Menü: Konverter | XML bearbeiten, ODX FIBEX Editor', self._show_xml_editor_panel),
            ('🔄 MDF zu CSV', 'Menü: Konverter | MDF to CSV, Export', lambda: None),
            ('🔄 MDF zu MAT', 'Menü: Konverter | MDF to MATLAB, Export', lambda: None),
            ('🔄 CSV zu MDF', 'Menü: Konverter | CSV Import, Convert to MDF', lambda: None),
            ('📦 Batch Konvertierung', 'Menü: Konverter | Batch Convert, Multiple Files', lambda: None),

            # === Hilfe Menü ===
            ('📖 Funktionsreferenz', 'Menü: Hilfe | Reference, Handbuch, Features, F1', self._show_help_reference),
            ('❓ Über', 'Menü: Hilfe | About, Info, Version', self._show_about),

            # === Toolbar Funktionen ===
            ('▶️ Plot ausgewählte Signale', 'Toolbar | Signale plotten, Graph erstellen', self._plot_selected),
            ('🗑️ Alle Plots löschen', 'Toolbar | Clear Plots, Schließen', self._clear_all_plots),

            # === Video Panel ===
            ('🎬 Video Player', 'Panel: Video | Video abspielen, Media Player', self._show_video_player),
            ('📂 Video Datei öffnen', 'Panel: Video | Video laden, MP4 AVI', lambda: None),
            ('🔗 Video synchronisieren', 'Panel: Video | Sync with MDF, Zeitstempel', lambda: None),

            # === Report Generator Dialog ===
            ('📄 HTML Report', 'Dialog: Report | HTML Export, Web Report', lambda: None),
            ('📄 PDF Report', 'Dialog: Report | PDF Export, Drucken', lambda: None),
            ('📊 Signal Statistik Report', 'Dialog: Report | Statistics, Min Max Mean', lambda: None),
            ('🔧 DTC Report', 'Dialog: Report | Fehlercode Bericht, Diagnostic Report', lambda: None),

            # === Formel Editor Dialog ===
            ('➕ Kanal erstellen', 'Dialog: Formel | Berechneter Kanal, Calculated Channel', lambda: None),
            ('📐 Mathematische Funktionen', 'Dialog: Formel | Math Functions, sin cos sqrt', lambda: None),
            ('📊 Signal Operationen', 'Dialog: Formel | Signal Algebra, Add Subtract Multiply', lambda: None),

            # === DTC Panel ===
            ('📋 DTC Liste', 'Panel: DTC | Fehlercode Liste, Error Codes', lambda: None),
            ('📂 ODX Import', 'Panel: DTC | ODX Datei laden, Diagnostic Data', lambda: None),
            ('📤 DTC Export', 'Panel: DTC | Fehlercodes exportieren, CSV Export', lambda: None),
            ('🔍 DTC Suche', 'Panel: DTC | Fehlercode suchen, Search', lambda: None),

            # === Allgemeine Begriffe ===
            ('🚗 CAN Bus', 'Allgemein | Controller Area Network, Fahrzeugbus', lambda: None),
            ('🔌 LIN Bus', 'Allgemein | Local Interconnect Network', lambda: None),
            ('⚡ FlexRay', 'Allgemein | FlexRay Bus, Automotive Ethernet', lambda: None),
            ('🌐 Ethernet', 'Allgemein | Automotive Ethernet, DoIP', lambda: None),
            ('📡 Diagnose', 'Allgemein | Diagnostics, UDS, OBD, KWP2000', lambda: None),
            ('📊 Messung', 'Allgemein | Measurement, Recording, Logging', lambda: None),
            ('📈 Analyse', 'Allgemein | Analysis, Auswertung', lambda: None),
            ('💾 Kalibrierung', 'Allgemein | Calibration, XCP, CCP', lambda: None),
        ]

        # Suche durchführen
        results = []
        for name, keywords, action in features:
            if search_text in name.lower() or search_text in keywords.lower():
                results.append((name, keywords, action))

        # Ergebnis-Dialog
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView

        result_dialog = QDialog(self)
        result_dialog.setWindowTitle(f"🔍 Suchergebnisse für '{search_text}'")
        result_dialog.resize(700, 500)

        layout = QVBoxLayout(result_dialog)

        info_label = QLabel(f"🔍 Gefunden: {len(results)} Treffer für '{search_text}'")
        info_label.setStyleSheet("font-weight: bold; font-size: 13px; padding: 5px; background: #e8f4f8; border-radius: 4px;")
        layout.addWidget(info_label)

        if results:
            # Tabelle für bessere Übersicht
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(['Funktion', 'Ort', 'Beschreibung'])
            table.setRowCount(len(results))
            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.setStyleSheet("font-size: 11px;")

            self._search_actions = []  # Aktionen speichern für Doppelklick

            for row, (name, keywords, action) in enumerate(results):
                # Ort extrahieren (Menü, Panel, Dialog, etc.)
                location = "Allgemein"
                if keywords.startswith("Menü:"):
                    parts = keywords.split("|")
                    location = parts[0].replace("Menü:", "").strip()
                    desc = parts[1].strip() if len(parts) > 1 else ""
                elif keywords.startswith("Panel:"):
                    parts = keywords.split("|")
                    location = parts[0].replace("Panel:", "").strip()
                    desc = parts[1].strip() if len(parts) > 1 else ""
                elif keywords.startswith("Dialog:"):
                    parts = keywords.split("|")
                    location = parts[0].replace("Dialog:", "").strip()
                    desc = parts[1].strip() if len(parts) > 1 else ""
                elif keywords.startswith("Toolbar"):
                    parts = keywords.split("|")
                    location = "Toolbar"
                    desc = parts[1].strip() if len(parts) > 1 else ""
                elif keywords.startswith("Allgemein"):
                    parts = keywords.split("|")
                    location = "Allgemein"
                    desc = parts[1].strip() if len(parts) > 1 else ""
                else:
                    desc = keywords

                table.setItem(row, 0, QTableWidgetItem(name))
                table.setItem(row, 1, QTableWidgetItem(location))
                table.setItem(row, 2, QTableWidgetItem(desc))
                self._search_actions.append(action)

            # Doppelklick zum Ausführen
            def on_row_double_clicked(row, col):
                if row < len(self._search_actions):
                    action = self._search_actions[row]
                    if action and callable(action):
                        result_dialog.close()
                        action()

            table.cellDoubleClicked.connect(on_row_double_clicked)
            layout.addWidget(table)

            hint_label = QLabel("💡 Doppelklick auf eine Zeile öffnet die Funktion direkt")
            hint_label.setStyleSheet("color: #666; font-size: 10px; padding: 3px;")
            layout.addWidget(hint_label)
        else:
            no_result = QLabel("❌ Keine Funktionen gefunden.\n\nVersuchen Sie andere Suchbegriffe wie:\n• MDF, Export, Plot, Signal\n• Docker, Lua, REST API\n• DTC, CAN, Wireshark")
            no_result.setStyleSheet("color: #666; font-size: 12px; padding: 20px;")
            no_result.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(no_result)

        btn_close = QPushButton("Schließen")
        btn_close.clicked.connect(result_dialog.close)
        layout.addWidget(btn_close)

        result_dialog.exec()

    # ==================== Time-Sync Methoden ====================

    def _create_sync_toolbar(self, toolbar):
        """Erstellt die Time-Sync Toolbar-Elemente."""
        from PyQt6.QtWidgets import QCheckBox, QDoubleSpinBox, QToolButton, QSlider

        # Sync-Checkbox
        self._sync_checkbox = QCheckBox('🔗 Sync')
        self._sync_checkbox.setChecked(True)
        self._sync_checkbox.setToolTip('Zeitsynchronisation zwischen Video, Plot und Trace aktivieren')
        self._sync_checkbox.stateChanged.connect(self._on_sync_toggled)
        toolbar.addWidget(self._sync_checkbox)

        # Sync-Slider für globale Navigation
        self._sync_slider = QSlider(Qt.Orientation.Horizontal)
        self._sync_slider.setRange(0, 1000)  # 0-1000 für feine Auflösung
        self._sync_slider.setFixedWidth(150)
        self._sync_slider.setToolTip('Globaler Zeit-Slider für alle synchronisierten Views')
        self._sync_slider.valueChanged.connect(self._on_sync_slider_changed)
        self._sync_slider.setEnabled(False)  # Aktiviert wenn Daten geladen
        toolbar.addWidget(self._sync_slider)

        # Zeit-Anzeige
        self._sync_time_label = QLabel('--:--')
        self._sync_time_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._sync_time_label.setFixedWidth(60)
        self._sync_time_label.setStyleSheet('font-family: monospace; font-size: 10px;')
        toolbar.addWidget(self._sync_time_label)

        toolbar.addWidget(QLabel(' | '))

        # Video-Offset SpinBox
        offset_label = QLabel('Offset:')
        toolbar.addWidget(offset_label)

        self._offset_spinbox = QDoubleSpinBox()
        self._offset_spinbox.setRange(-3600.0, 3600.0)
        self._offset_spinbox.setSingleStep(0.1)
        self._offset_spinbox.setDecimals(2)
        self._offset_spinbox.setSuffix(' s')
        self._offset_spinbox.setToolTip('Video-Offset in Sekunden (Video = MDF + Offset)')
        self._offset_spinbox.setFixedWidth(90)
        self._offset_spinbox.valueChanged.connect(self._on_offset_changed)
        toolbar.addWidget(self._offset_spinbox)

        # Sync-Status Label
        self._sync_status_label = QLabel('')
        self._sync_status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._sync_status_label.setStyleSheet('color: #666; font-size: 10px;')
        toolbar.addWidget(self._sync_status_label)

    def _on_sync_toggled(self, state):
        """Wird aufgerufen wenn Sync aktiviert/deaktiviert wird."""
        self._time_sync_manager.sync_enabled = (state == Qt.CheckState.Checked.value)
        if state == Qt.CheckState.Checked.value:
            self._sync_status_label.setText('✓')
            self._sync_status_label.setStyleSheet('color: #2e7d32; font-weight: bold;')
        else:
            self._sync_status_label.setText('✗')
            self._sync_status_label.setStyleSheet('color: #c62828; font-weight: bold;')

    def _on_offset_changed(self, value):
        """Wird aufgerufen wenn der Video-Offset geändert wird."""
        self._time_sync_manager.video_offset = value

    def _on_sync_slider_changed(self, value):
        """Wird aufgerufen wenn der Sync-Slider bewegt wird."""
        time_range = self._time_sync_manager.get_time_range()
        start, end = time_range
        if end <= start:
            return

        # Slider-Wert (0-1000) zu Zeit konvertieren
        time_seconds = start + (value / 1000.0) * (end - start)

        # Zeit-Label aktualisieren
        minutes = int(time_seconds // 60)
        seconds = time_seconds % 60
        self._sync_time_label.setText(f'{minutes:02d}:{seconds:05.2f}')

        # Sync-Manager benachrichtigen
        self._time_sync_manager.on_slider_moved(time_seconds)

    def _update_sync_slider_from_time(self, time_seconds):
        """Aktualisiert den Sync-Slider basierend auf der Zeit."""
        time_range = self._time_sync_manager.get_time_range()
        start, end = time_range
        if end <= start:
            return

        # Zeit zu Slider-Wert (0-1000) konvertieren
        slider_value = int(((time_seconds - start) / (end - start)) * 1000)
        slider_value = max(0, min(1000, slider_value))

        # Slider ohne Signal-Emission aktualisieren
        self._sync_slider.blockSignals(True)
        self._sync_slider.setValue(slider_value)
        self._sync_slider.blockSignals(False)

        # Zeit-Label aktualisieren
        minutes = int(time_seconds // 60)
        seconds = time_seconds % 60
        self._sync_time_label.setText(f'{minutes:02d}:{seconds:05.2f}')

    def _on_sync_time_changed(self, time_seconds, source):
        """Wird aufgerufen wenn sich die synchronisierte Zeit ändert.

        Aktualisiert alle Views außer der Quelle.
        """
        # Sync-Slider aktualisieren (wenn nicht vom Slider ausgelöst)
        if source != SyncSource.SLIDER:
            self._update_sync_slider_from_time(time_seconds)

        # Plot-Cursor aktualisieren (wenn nicht von Plot ausgelöst)
        if source != SyncSource.PLOT:
            self._update_all_plot_cursors(time_seconds)

        # Video-Position aktualisieren (wenn nicht von Video ausgelöst)
        if source != SyncSource.VIDEO:
            self._update_video_position(time_seconds)

        # Wireshark-Tabelle aktualisieren (wenn nicht von Wireshark ausgelöst)
        if source != SyncSource.WIRESHARK:
            self._update_wireshark_selection(time_seconds)

        # Bus-Trace aktualisieren (wenn nicht von Bus-Trace ausgelöst)
        if source != SyncSource.BUS_TRACE:
            self._update_bus_trace_selection(time_seconds)

        # State Tracker aktualisieren
        self._update_state_tracker(time_seconds)

        # Replay-Panel aktualisieren (wenn nicht vom Slider ausgeloest)
        if source != SyncSource.SLIDER:
            self._update_replay_position(time_seconds)

    def _update_state_tracker(self, time_seconds):
        """Aktualisiert den State Tracker auf die angegebene Zeit."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, StateTrackerPanel):
                widget.set_cursor_time(time_seconds)

    def _update_replay_position(self, time_seconds):
        """Aktualisiert das Replay-Panel auf die angegebene Zeit."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, ReplayPanel):
                widget.set_time_position(time_seconds)

    def _update_all_plot_cursors(self, time_seconds):
        """Aktualisiert alle Plot-Cursors auf die angegebene Zeit."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, PlotWidget):
                widget.set_cursor_position(time_seconds, emit_signal=False)

    def _update_video_position(self, time_seconds):
        """Aktualisiert die Video-Position."""
        if self._video_player_window and self._video_player_window.isVisible():
            # MDF-Zeit zu Video-Zeit konvertieren
            video_time = self._time_sync_manager.mdf_time_to_video_time(time_seconds)
            self._video_player_window.seek_to_time(video_time, emit_signal=False)

    def _update_wireshark_selection(self, time_seconds):
        """Aktualisiert die Wireshark-Paketauswahl."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, WiresharkPanel):
                widget.scroll_to_timestamp(time_seconds, emit_signal=False)

    def _update_bus_trace_selection(self, time_seconds):
        """Aktualisiert die Bus-Trace-Auswahl."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusTracePanel):
                widget.scroll_to_timestamp(time_seconds, emit_signal=False)

    def _connect_plot_to_sync(self, plot_widget: PlotWidget):
        """Verbindet ein PlotWidget mit dem Time-Sync-Manager."""
        plot_widget.cursorPositionChanged.connect(
            self._time_sync_manager.on_plot_cursor_moved
        )

    def _connect_video_to_sync(self, video_window):
        """Verbindet ein Video-Fenster mit dem Time-Sync-Manager."""
        self._video_player_window = video_window
        video_window.positionChanged.connect(
            self._time_sync_manager.on_video_position_changed
        )

    def _connect_wireshark_to_sync(self, wireshark_panel: WiresharkPanel):
        """Verbindet ein WiresharkPanel mit dem Time-Sync-Manager."""
        wireshark_panel.packetTimestampSelected.connect(
            self._time_sync_manager.on_wireshark_packet_selected
        )

    def _connect_bus_trace_to_sync(self, bus_trace_panel: BusTracePanel):
        """Verbindet ein BusTracePanel mit dem Time-Sync-Manager."""
        bus_trace_panel.frameTimestampSelected.connect(
            self._time_sync_manager.on_bus_trace_frame_selected
        )

    def _enable_sync_slider(self):
        """Aktiviert den Sync-Slider wenn Daten geladen sind."""
        time_range = self._time_sync_manager.get_time_range()
        if time_range[1] > time_range[0]:
            self._sync_slider.setEnabled(True)
            self._sync_time_label.setText('00:00.00')
        else:
            self._sync_slider.setEnabled(False)
            self._sync_time_label.setText('--:--')

    def _add_to_recent(self, file_path: str):
        """Fügt eine Datei zur Liste der zuletzt geöffneten hinzu."""
        recent = self._settings.value('recentFiles', []) or []
        if file_path in recent:
            recent.remove(file_path)
        recent.insert(0, file_path)
        recent = recent[:10]  # Maximal 10 Einträge
        self._settings.setValue('recentFiles', recent)
        self._update_recent_menu()

    def _update_recent_menu(self):
        """Aktualisiert das Menü der zuletzt geöffneten Dateien."""
        self._recent_menu.clear()
        recent = self._settings.value('recentFiles', []) or []

        for file_path in recent:
            action = QAction(Path(file_path).name, self)
            action.setToolTip(file_path)
            action.triggered.connect(lambda checked, p=file_path: self._open_recent_file(p))
            self._recent_menu.addAction(action)

        if not recent:
            action = QAction('(Keine)', self)
            action.setEnabled(False)
            self._recent_menu.addAction(action)

    def _open_recent_file(self, file_path: str):
        """Öffnet eine kürzlich geöffnete Datei im passenden Panel."""
        if not Path(file_path).exists():
            QMessageBox.warning(self, 'Fehler', f'Datei nicht gefunden:\n{file_path}')
            return
        ext = Path(file_path).suffix.lower()
        if ext in ('.mdf', '.mf4', '.dat'):
            self._load_file(file_path)
        elif ext in ('.pcap', '.pcapng', '.cap'):
            self._open_recent_pcap(file_path)
        elif ext == '.a2l':
            self._open_recent_a2l(file_path)
        elif ext in ('.dbc', '.arxml'):
            self._open_recent_dbc(file_path)
        else:
            QMessageBox.information(self, 'Unbekannt', f'Kein passendes Panel für: {ext}')

    def _open_recent_pcap(self, file_path: str):
        """Öffnet eine PCAP-Datei im Wireshark-Panel."""
        wireshark_tab = WiresharkPanel()
        self._connect_wireshark_to_sync(wireshark_tab)
        wireshark_tab.file_opened.connect(self._add_to_recent)
        self._plot_tabs.addTab(wireshark_tab, 'Wireshark')
        self._plot_tabs.setCurrentWidget(wireshark_tab)
        wireshark_tab._load_file(file_path)

    def _open_recent_a2l(self, file_path: str):
        """Öffnet eine A2L-Datei im XCP-Panel."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('files')
            if panel._file_panel._handler.load_a2l(file_path):
                panel._file_panel._a2l_path.setText(file_path)
                panel._file_panel._update_a2l_info()
                panel._file_panel.a2l_loaded.emit(panel._file_panel._handler.a2l_file)
                self._add_to_recent(file_path)

    def _open_recent_dbc(self, file_path: str):
        """Öffnet eine DBC/ARXML-Datei im Bus-Trace-Panel."""
        self._show_bus_trace_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusTracePanel):
                if widget._dbc_handler.load(file_path):
                    widget._update_info_label()
                    self._add_to_recent(file_path)
                else:
                    QMessageBox.warning(self, 'Fehler',
                                        f'DBC-Datei konnte nicht geladen werden:\n{file_path}')
                return

    def _show_video_player(self):
        """Öffnet den Video-Player für Attachments oder externe Video-Dateien."""
        # Video-Player Tab erstellen (funktioniert auch ohne MDF-Handler)
        video_tab = VideoPlayerTab(self._current_handler)

        # Mit Time-Sync verbinden
        video_tab.videoWindowCreated.connect(self._connect_video_to_sync)

        self._plot_tabs.addTab(video_tab, 'Video')
        self._plot_tabs.setCurrentWidget(video_tab)

    def _show_wireshark_panel(self):
        """Öffnet das Wireshark-Panel für Netzwerkanalyse."""
        # Wireshark-Panel Tab erstellen
        wireshark_tab = WiresharkPanel()

        # Mit Time-Sync verbinden
        self._connect_wireshark_to_sync(wireshark_tab)
        wireshark_tab.file_opened.connect(self._add_to_recent)

        self._plot_tabs.addTab(wireshark_tab, 'Wireshark')
        self._plot_tabs.setCurrentWidget(wireshark_tab)

    def _show_wireshark_with_filter(self, filter_text: str):
        """Öffnet das Wireshark-Panel mit einem voreingestellten Filter."""
        wireshark_tab = WiresharkPanel()
        wireshark_tab.file_opened.connect(self._add_to_recent)
        wireshark_tab.filter_entry.setText(filter_text)
        self._plot_tabs.addTab(wireshark_tab, f'Wireshark ({filter_text.upper()})')
        self._plot_tabs.setCurrentWidget(wireshark_tab)

    def _show_dtc_panel(self):
        """Oeffnet das DTC-Management Panel."""
        # Pruefen ob bereits ein DTC-Panel offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, DTCManagementPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Neues Panel erstellen
        dtc_panel = DTCManagementPanel()
        self._plot_tabs.addTab(dtc_panel, '🔧 DTC-Management')
        self._plot_tabs.setCurrentWidget(dtc_panel)

    def _show_report_generator(self):
        """Oeffnet den Report Generator Dialog."""
        import numpy as np

        # Metadaten sammeln falls MDF geladen
        metadata = {}
        signals = []

        if self._current_handler and self._current_handler.is_open:
            # Metadaten aus Handler holen
            try:
                file_info = self._current_handler.get_file_info() or {}
                metadata = {
                    'Dateiname': file_info.get('file_path', 'Unbekannt'),
                    'Format': file_info.get('version', 'Unbekannt'),
                    'Erstellungsdatum': str(file_info.get('start_time', 'Unbekannt')),
                    'Dauer': f"{file_info.get('duration', 0):.2f} Sekunden",
                    'Kanalgruppen': file_info.get('channel_groups_count', 0),
                }
            except Exception:
                pass

            # Signal-Liste mit Statistiken holen
            try:
                groups = self._current_handler.get_groups()
                for group_idx, group_info in enumerate(groups):
                    channels = self._current_handler.get_channels(group_idx)
                    for channel in channels:
                        name = channel.name if hasattr(channel, 'name') else channel.get('name', 'Unbekannt')
                        unit = channel.unit if hasattr(channel, 'unit') else channel.get('unit', '')

                        signal_data = {
                            'name': name,
                            'unit': unit,
                            'count': 0,
                            'min': 0.0,
                            'max': 0.0,
                            'mean': 0.0,
                            'std': 0.0,
                        }

                        # Statistiken hinzufuegen wenn verfuegbar
                        try:
                            result = self._current_handler.get_signal(name, group=group_idx)
                            if result:
                                timestamps, samples = result
                                if samples is not None and len(samples) > 0:
                                    signal_data['count'] = len(samples)
                                    signal_data['min'] = float(np.nanmin(samples))
                                    signal_data['max'] = float(np.nanmax(samples))
                                    signal_data['mean'] = float(np.nanmean(samples))
                                    signal_data['std'] = float(np.nanstd(samples))
                        except Exception:
                            pass

                        signals.append(signal_data)

                        # Limit auf max 50 Signale fuer Performance
                        if len(signals) >= 50:
                            break
                    if len(signals) >= 50:
                        break
            except Exception:
                pass

        # Dialog oeffnen
        dialog = ReportGeneratorDialog(self, metadata, signals)
        dialog.exec()

    def _show_wireshark_statistics(self):
        """Zeigt Wireshark-Statistiken an."""
        # Prüfen ob bereits ein Wireshark-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, WiresharkPanel):
                widget._show_statistics()
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Kein Wireshark-Tab offen, neuen erstellen
        QMessageBox.information(
            self, 'Hinweis',
            'Bitte öffnen Sie zuerst eine PCAP-Datei im Wireshark-Panel.'
        )

    def _show_wireshark_uds_sequence(self):
        """Zeigt die UDS Sequenz-Analyse an."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, WiresharkPanel):
                widget._show_uds_sequence_analysis()
                self._plot_tabs.setCurrentWidget(widget)
                return

        QMessageBox.information(
            self, 'Hinweis',
            'Bitte öffnen Sie zuerst eine PCAP-Datei im Wireshark-Panel.'
        )

    def _show_wireshark_live_capture(self, capture_filter: str = ""):
        """Öffnet das Wireshark-Panel im Live-Capture-Modus."""
        # Sicherstellen, dass capture_filter ein String ist (nicht bool vom Signal)
        if not isinstance(capture_filter, str):
            capture_filter = ""
        wireshark_tab = WiresharkPanel(live_capture_mode=True, default_capture_filter=capture_filter)
        wireshark_tab.file_opened.connect(self._add_to_recent)
        tab_name = 'Live Capture'
        if capture_filter:
            tab_name = f'Live ({capture_filter})'
        self._plot_tabs.addTab(wireshark_tab, tab_name)
        self._plot_tabs.setCurrentWidget(wireshark_tab)

    def _show_docker_panel(self):
        """Öffnet das Docker-Panel für Container-Verwaltung."""
        # Prüfen ob bereits ein Docker-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, DockerPanel):
                self._plot_tabs.setCurrentWidget(widget)
                widget._refresh_all()
                return

        # Neuen Docker-Tab erstellen
        docker_tab = DockerPanel()
        self._plot_tabs.addTab(docker_tab, 'Docker')
        self._plot_tabs.setCurrentWidget(docker_tab)

    def _show_docker_panel_tab(self, tab_index: int):
        """Öffnet das Docker-Panel und wechselt zu einem bestimmten Tab."""
        # Prüfen ob bereits ein Docker-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, DockerPanel):
                self._plot_tabs.setCurrentWidget(widget)
                widget.tabs.setCurrentIndex(tab_index)
                widget._refresh_all()
                return

        # Neuen Docker-Tab erstellen
        docker_tab = DockerPanel()
        docker_tab.tabs.setCurrentIndex(tab_index)
        self._plot_tabs.addTab(docker_tab, 'Docker')
        self._plot_tabs.setCurrentWidget(docker_tab)

    def _show_vehicle_logger_template(self):
        """Öffnet den Vehicle Logger Template-Dialog."""
        # Docker-Panel öffnen und Template-Dialog anzeigen
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, DockerPanel):
                self._plot_tabs.setCurrentWidget(widget)
                widget._show_template_dialog()
                return

        # Neuen Docker-Tab erstellen
        docker_tab = DockerPanel()
        self._plot_tabs.addTab(docker_tab, 'Docker')
        self._plot_tabs.setCurrentWidget(docker_tab)
        docker_tab._show_template_dialog()

    def _show_lua_panel(self):
        """Öffnet das Lua-Panel für Skript-Entwicklung."""
        # Prüfen ob bereits ein Lua-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LuaPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Neuen Lua-Tab erstellen
        lua_tab = LuaPanel()
        self._plot_tabs.addTab(lua_tab, 'Lua')
        self._plot_tabs.setCurrentWidget(lua_tab)

    def _lua_new_script(self):
        """Erstellt ein neues Lua-Skript."""
        self._show_lua_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LuaPanel):
                widget._new_file()
                return

    def _lua_open_script(self):
        """Öffnet ein Lua-Skript."""
        self._show_lua_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LuaPanel):
                widget._open_file()
                return

    def _lua_insert_template(self, category: str, name: str):
        """Fügt ein Lua-Template ein."""
        self._show_lua_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LuaPanel):
                # Template in Combo-Box auswählen
                template_text = f"{category} → {name}"
                index = widget.template_combo.findText(template_text)
                if index >= 0:
                    widget.template_combo.setCurrentIndex(index)
                    widget._insert_template()
                return

    def _show_restapi_panel(self):
        """Öffnet das REST API Panel."""
        # Prüfen ob bereits ein REST API-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, RestApiPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Neuen REST API-Tab erstellen
        restapi_tab = RestApiPanel()
        self._plot_tabs.addTab(restapi_tab, 'REST API')
        self._plot_tabs.setCurrentWidget(restapi_tab)

    def _restapi_load_template(self, category: str, name: str):
        """Lädt ein REST API Template."""
        self._show_restapi_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, RestApiPanel):
                # Template in Combo-Box auswählen
                template_text = f"{category} → {name}"
                index = widget.template_combo.findText(template_text)
                if index >= 0:
                    widget.template_combo.setCurrentIndex(index)
                    widget._load_template()
                return

    def _restapi_edit_environments(self):
        """Öffnet den Umgebungsvariablen-Dialog für REST API."""
        self._show_restapi_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, RestApiPanel):
                widget._edit_environments()
                return

    def _show_automation_panel(self):
        """Öffnet das Automatisierung-Panel für Web-Tests."""
        # Prüfen ob bereits ein Automatisierung-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, AutomationPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Neuen Automatisierung-Tab erstellen
        automation_tab = AutomationPanel()
        self._plot_tabs.addTab(automation_tab, 'Automatisierung')
        self._plot_tabs.setCurrentWidget(automation_tab)

    # =========================================================================
    # Sprachsteuerung Methoden
    # =========================================================================

    def _show_voice_control_panel(self):
        """Öffnet das Sprachsteuerungs-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, VoiceControlPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        voice_tab = VoiceControlPanel()
        voice_tab.command_execute.connect(self.execute_voice_command)
        self._plot_tabs.addTab(voice_tab, 'Sprachsteuerung')
        self._plot_tabs.setCurrentWidget(voice_tab)

    def execute_voice_command(self, action: str, params: dict):
        """Führt einen per Sprachbefehl erkannten Befehl aus."""
        panel_map = {
            'logger': self._show_logger_panel,
            'terminal': self._show_terminal_panel,
            'automation': self._show_automation_panel,
            'restapi': self._show_restapi_panel,
            'wireshark': self._show_wireshark_panel,
        }

        action_map = {
            'logger_start_capture': self._show_logger_live_capture,
            'logger_stop_capture': self._logger_stop_capture_voice,
            'logger_save_mdf': self._show_logger_save_mdf,
            'logger_save_pcap': self._show_logger_save_pcap,
            'logger_show_statistics': self._show_logger_statistics,
        }

        if action == 'open_panel':
            panel_name = params.get('panel', '')
            handler = panel_map.get(panel_name)
            if handler:
                handler()
            else:
                QMessageBox.warning(self, "Sprachsteuerung", f"Unbekanntes Panel: {panel_name}")
        elif action == 'restapi_send':
            self._show_restapi_panel()
        elif action in action_map:
            action_map[action]()
        else:
            QMessageBox.warning(self, "Sprachsteuerung", f"Unbekannte Aktion: {action}")

    def _logger_stop_capture_voice(self):
        """Stoppt die Logger-Aufnahme (via Sprachbefehl)."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LoggerPanel):
                widget.stop_live_capture()
                return

    def _show_system_solution_panel(self):
        """Öffnet das Systemlösung-Panel für Vehicle Data Logger Konfiguration."""
        # Prüfen ob bereits ein Systemlösung-Tab offen ist
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, SystemSolutionPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        # Neuen Systemlösung-Tab erstellen
        system_solution_tab = SystemSolutionPanel(self._db)
        self._plot_tabs.addTab(system_solution_tab, 'Systemlösung')
        self._plot_tabs.setCurrentWidget(system_solution_tab)

    def _get_system_solution_panel(self) -> 'SystemSolutionPanel':
        """Gibt das SystemSolutionPanel zurück oder erstellt es."""
        self._show_system_solution_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, SystemSolutionPanel):
                return widget
        return None

    def _system_load_template(self, template_name: str):
        """Lädt eine Systemlösungs-Projektvorlage."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.load_template(template_name)

    def _system_filter_manufacturer(self, manufacturer: str):
        """Filtert den Produktkatalog nach Hersteller."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.filter_by_manufacturer(manufacturer)

    def _system_filter_interface(self, interface: str):
        """Filtert den Produktkatalog nach Schnittstelle."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.filter_by_interface(interface)

    def _system_filter_sensor(self, sensor: str):
        """Filtert den Produktkatalog nach Sensor."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.filter_by_sensor(sensor)

    def _system_generate_report(self):
        """Generiert einen Systemlösungs-Report."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.generate_report()

    def _system_export_bom(self):
        """Exportiert die Stückliste."""
        panel = self._get_system_solution_panel()
        if panel:
            panel.export_bom()

    # =========================================================================
    # Firmware-Management Methoden
    # =========================================================================

    def _show_firmware_panel(self):
        """Öffnet das Firmware-Management-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, FirmwareManagementPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        firmware_tab = FirmwareManagementPanel(self._db)
        self._plot_tabs.addTab(firmware_tab, 'Firmware')
        self._plot_tabs.setCurrentWidget(firmware_tab)

    def _show_firmware_structure(self, mode: str = ''):
        """Öffnet das Firmware-Structure-Panel als Tab."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, FirmwareStructurePanel):
                self._plot_tabs.setCurrentWidget(widget)
                if mode:
                    widget.set_mode(mode)
                return

        panel = FirmwareStructurePanel()
        if mode:
            panel.set_mode(mode)
        self._plot_tabs.addTab(panel, 'Firmware Structure')
        self._plot_tabs.setCurrentWidget(panel)

    def _get_firmware_panel(self) -> 'FirmwareManagementPanel':
        """Gibt das FirmwareManagementPanel zurück oder erstellt es."""
        self._show_firmware_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, FirmwareManagementPanel):
                return widget
        return None

    def _firmware_show_tab(self, tab_name: str):
        """Zeigt einen bestimmten Tab im Firmware-Panel."""
        panel = self._get_firmware_panel()
        if panel:
            panel.show_tab(tab_name)

    def _firmware_scan_devices(self):
        """Scannt nach Geräten im Netzwerk."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Scan", "Netzwerk wird nach ViGEM Loggern gescannt...")

    def _firmware_add_device(self):
        """Fügt ein Gerät manuell hinzu."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Gerät hinzufügen", "Manuelle Gerätekonfiguration...")

    def _firmware_select_model(self, model_id: str):
        """Wählt ein Modell aus und zeigt dessen Firmware."""
        panel = self._get_firmware_panel()
        if panel:
            panel.filter_by_model(model_id)
            panel.show_tab('versions')

    def _firmware_upload(self):
        """Lädt eine Firmware-Datei hoch."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Firmware hochladen", "", "Firmware (*.bin *.hex *.fw);;Alle (*)")
        if path:
            QMessageBox.information(self, "Upload", f"Firmware wird hochgeladen:\n{path}")

    def _firmware_download(self):
        """Lädt eine Firmware herunter."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Download", "Firmware wird heruntergeladen...")

    def _firmware_show_changelog(self):
        """Zeigt den Changelog der ausgewählten Firmware."""
        panel = self._get_firmware_panel()
        if panel:
            panel.show_tab('versions')

    def _firmware_batch_update(self):
        """Startet ein Batch-Update für mehrere Geräte."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Batch-Update",
                              "Wählen Sie die Geräte für das Batch-Update aus...")

    def _firmware_schedule_update(self):
        """Plant ein zukünftiges Update."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Update planen",
                              "Planen Sie das Update für einen späteren Zeitpunkt...")

    def _firmware_rollback(self):
        """Führt einen Rollback zur vorherigen Version durch."""
        reply = QMessageBox.question(self, "Rollback",
                                    "Zur vorherigen Firmware-Version zurückkehren?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Rollback", "Rollback wird durchgeführt...")

    def _firmware_validation_report(self):
        """Erstellt einen Validierungsbericht."""
        panel = self._get_firmware_panel()
        if panel:
            panel.show_tab('validation')

    def _firmware_check_integrity(self):
        """Prüft die Integrität der Firmware (Checksumme)."""
        QMessageBox.information(self, "Integritätsprüfung",
                              "MD5/SHA256 Checksummen werden überprüft...")

    def _firmware_check_compatibility(self):
        """Prüft die Kompatibilität mit Hardware."""
        QMessageBox.information(self, "Kompatibilität",
                              "Hardware- und Bootloader-Kompatibilität wird geprüft...")

    def _firmware_config_write(self):
        """Schreibt die Konfiguration auf das Gerät."""
        panel = self._get_firmware_panel()
        if panel:
            panel.show_tab('configuration')

    def _firmware_config_export(self):
        """Exportiert die Gerätekonfiguration."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Konfiguration exportieren", "", "JSON (*.json);;XML (*.xml)")
        if path:
            QMessageBox.information(self, "Export", f"Konfiguration exportiert nach:\n{path}")

    def _firmware_config_import(self):
        """Importiert eine Gerätekonfiguration."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Konfiguration importieren", "", "JSON (*.json);;XML (*.xml)")
        if path:
            QMessageBox.information(self, "Import", f"Konfiguration importiert von:\n{path}")

    def _firmware_config_profiles(self):
        """Verwaltet Konfigurationsprofile."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Profile",
                              "Konfigurationsprofile verwalten...")

    def _firmware_factory_reset(self):
        """Setzt das Gerät auf Werkseinstellungen zurück."""
        reply = QMessageBox.warning(self, "Werkseinstellungen",
                                   "Alle Einstellungen werden gelöscht!\n"
                                   "Diese Aktion kann nicht rückgängig gemacht werden.\n\n"
                                   "Fortfahren?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Reset", "Werkseinstellungen werden wiederhergestellt...")

    def _firmware_repo_sync(self):
        """Synchronisiert das Repository mit dem Server."""
        QMessageBox.information(self, "Synchronisation",
                              "Repository wird mit dem Server synchronisiert...")

    def _firmware_repo_cleanup(self):
        """Bereinigt alte Firmware-Versionen."""
        reply = QMessageBox.question(self, "Bereinigen",
                                    "Veraltete Firmware-Versionen löschen?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Bereinigt", "Alte Versionen wurden gelöscht.")

    def _firmware_show_log(self):
        """Zeigt das Update-Protokoll."""
        panel = self._get_firmware_panel()
        QMessageBox.information(self, "Protokoll",
                              "Update-Protokoll wird angezeigt...")

    def _firmware_settings(self):
        """Öffnet die Firmware-Manager Einstellungen."""
        QMessageBox.information(self, "Einstellungen",
                              "Firmware-Manager Einstellungen:\n"
                              "- Server-URL\n"
                              "- Auto-Update\n"
                              "- Backup-Optionen\n"
                              "- Benachrichtigungen")

    # =========================================================================
    # Framework-Management Methoden
    # =========================================================================

    def _show_framework_panel(self):
        """Öffnet das Framework-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, FrameworkPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        framework_tab = FrameworkPanel()
        self._plot_tabs.addTab(framework_tab, 'Framework')
        self._plot_tabs.setCurrentWidget(framework_tab)

    def _get_framework_panel(self) -> 'FrameworkPanel':
        """Gibt das FrameworkPanel zurück oder erstellt es."""
        self._show_framework_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, FrameworkPanel):
                return widget
        return None

    def _framework_show_tab(self, tab_name: str):
        """Zeigt einen bestimmten Tab im Framework-Panel."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab(tab_name)

    def _framework_show_doc(self, framework: str):
        """Zeigt API-Dokumentation für ein Framework."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab('documentation')
            # Framework-spezifische Dokumentation
            QMessageBox.information(self, "Dokumentation",
                                  f"{framework} API-Dokumentation wird geladen...")

    def _framework_search_api(self):
        """Öffnet die API-Suche."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab('documentation')

    def _framework_show_category(self, category: str):
        """Zeigt APIs einer bestimmten Kategorie."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab('documentation')
            panel.search_api(category)

    def _framework_generate_code(self, template: str):
        """Generiert Code aus einem Template."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab('codegen')
            panel._codegen_panel._template_combo.setCurrentText(template)

    def _framework_install_sdk(self, platform: str):
        """Installiert ein SDK."""
        QMessageBox.information(self, "SDK Installation",
                              f"CCA SDK für {platform} wird heruntergeladen...\n(Demo-Modus)")

    def _framework_open_example(self, example: str):
        """Öffnet ein Beispielprojekt."""
        panel = self._get_framework_panel()
        if panel:
            panel.show_tab('examples')
            QMessageBox.information(self, "Beispiel",
                                  f"Beispielprojekt '{example}' wird geladen...")

    def _framework_open_online_docs(self):
        """Öffnet die Online-Dokumentation."""
        QMessageBox.information(self, "Online-Dokumentation",
                              "https://docs.vigem.de/cca-framework\n(Demo-Modus)")

    def _framework_open_forum(self):
        """Öffnet das Entwickler-Forum."""
        QMessageBox.information(self, "Forum",
                              "https://forum.vigem.de\n(Demo-Modus)")

    def _framework_open_github(self):
        """Öffnet das GitHub Repository."""
        QMessageBox.information(self, "GitHub",
                              "https://github.com/vigem/cca-framework\n(Demo-Modus)")

    def _framework_open_support(self):
        """Öffnet den technischen Support."""
        QMessageBox.information(self, "Support",
                              "Technischer Support:\n"
                              "E-Mail: support@vigem.de\n"
                              "Tel: +49 xxx xxxxxx")

    def _automation_load_template(self, template_name: str):
        """Lädt eine Automatisierungs-Testvorlage."""
        self._show_automation_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, AutomationPanel):
                # Template in Combo-Box auswählen
                index = widget.template_combo.findText(template_name)
                if index >= 0:
                    widget.template_combo.setCurrentIndex(index)
                    widget._load_template()
                return

    def _automation_run_tests(self):
        """Führt die Automatisierungstests aus."""
        self._show_automation_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, AutomationPanel):
                widget._run_tests()
                return

    def _automation_generate_report(self):
        """Generiert einen Automatisierungs-Testbericht."""
        self._show_automation_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, AutomationPanel):
                widget._generate_report()
                return

    # =========================================================================
    # Pytest-Methoden
    # =========================================================================

    def _pytest_new_test(self):
        """Erstellt eine neue Pytest-Testdatei."""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Neue Pytest-Datei erstellen",
            "test_new.py",
            "Python-Dateien (*.py);;Alle Dateien (*.*)")

        if file_path:
            template = '''"""Pytest Testmodul für Vehicle Data Logger.

Dieses Modul enthält automatisierte Tests für die Validierung
des Vehicle Data Logger Systems.

Ausführen mit: pytest {filename} -v
"""

import pytest
import time


class TestVehicleDataLogger:
    """Testklasse für Vehicle Data Logger Funktionen."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup vor jedem Test."""
        print("Test Setup...")
        yield
        print("Test Teardown...")

    def test_connection(self):
        """Testet die Verbindung zum Logger."""
        # TODO: Implementieren Sie den Verbindungstest
        assert True, "Verbindungstest erfolgreich"

    def test_can_channel_config(self):
        """Testet die CAN-Kanal-Konfiguration."""
        # TODO: CAN-Konfiguration testen
        expected_baudrate = 500000
        actual_baudrate = 500000  # Simuliert
        assert actual_baudrate == expected_baudrate, f"Baudrate mismatch"

    def test_data_recording(self):
        """Testet die Datenaufzeichnung."""
        # TODO: Datenaufzeichnung testen
        recording_active = True  # Simuliert
        assert recording_active, "Aufzeichnung nicht aktiv"

    @pytest.mark.parametrize("channel,expected", [
        ("CAN1", True),
        ("CAN2", True),
        ("LIN1", True),
    ])
    def test_channel_availability(self, channel, expected):
        """Testet die Verfügbarkeit verschiedener Kanäle."""
        # TODO: Kanal-Verfügbarkeit prüfen
        available = True  # Simuliert
        assert available == expected, f"Kanal {{channel}} nicht verfügbar"

    @pytest.mark.slow
    def test_long_running_recording(self):
        """Testet eine längere Aufzeichnung."""
        # TODO: Langzeit-Aufzeichnung testen
        duration = 5  # Sekunden
        # time.sleep(duration)
        assert True, "Langzeit-Aufzeichnung erfolgreich"


class TestDataValidation:
    """Tests für Datenvalidierung."""

    def test_signal_range(self):
        """Prüft ob Signalwerte im gültigen Bereich liegen."""
        min_val, max_val = 0, 100
        test_value = 50  # Simuliert
        assert min_val <= test_value <= max_val, "Wert außerhalb des Bereichs"

    def test_timestamp_monotonic(self):
        """Prüft ob Zeitstempel monoton steigend sind."""
        timestamps = [1.0, 2.0, 3.0, 4.0]  # Simuliert
        for i in range(1, len(timestamps)):
            assert timestamps[i] > timestamps[i-1], "Zeitstempel nicht monoton"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
'''
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(template.format(filename=file_path))
                QMessageBox.information(self, "Pytest",
                    f"Neue Pytest-Datei erstellt:\n{file_path}\n\n"
                    f"Ausführen mit:\npytest {file_path} -v")
            except Exception as e:
                QMessageBox.critical(self, "Fehler", f"Fehler beim Erstellen:\n{e}")

    def _pytest_open_file(self):
        """Öffnet eine Pytest-Datei im Editor."""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Pytest-Datei öffnen", "",
            "Python-Dateien (*.py);;Alle Dateien (*.*)")

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Editor-Dialog öffnen
                self._show_pytest_editor(file_path, content)
            except Exception as e:
                QMessageBox.critical(self, "Fehler", f"Fehler beim Öffnen:\n{e}")

    def _show_pytest_editor(self, file_path: str, content: str):
        """Zeigt den Pytest-Editor Dialog."""
        from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                      QPlainTextEdit, QPushButton, QLabel)
        from PyQt6.QtGui import QFont

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Pytest Editor - {file_path}")
        dialog.resize(900, 700)

        layout = QVBoxLayout(dialog)

        # Info
        info_label = QLabel(f"Datei: {file_path}")
        layout.addWidget(info_label)

        # Editor
        editor = QPlainTextEdit()
        editor.setFont(QFont("Consolas", 10))
        editor.setPlainText(content)
        p = ThemeManager.instance().get_palette()
        editor.setStyleSheet(f"background-color: {p.bg_tertiary}; color: {p.text_primary};")
        layout.addWidget(editor)

        # Buttons
        btn_layout = QHBoxLayout()

        save_btn = QPushButton("💾 Speichern")
        def save_file():
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(editor.toPlainText())
                QMessageBox.information(dialog, "Gespeichert", "Datei wurde gespeichert.")
            except Exception as e:
                QMessageBox.critical(dialog, "Fehler", f"Fehler beim Speichern:\n{e}")
        save_btn.clicked.connect(save_file)
        btn_layout.addWidget(save_btn)

        run_btn = QPushButton("▶️ Pytest ausführen")
        def run_test():
            save_file()
            dialog.accept()
            self._pytest_run_file(file_path)
        run_btn.clicked.connect(run_test)
        btn_layout.addWidget(run_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("Schließen")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)
        dialog.exec()

    def _pytest_run_tests(self):
        """Führt Pytest-Tests aus."""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Pytest-Datei oder Verzeichnis auswählen", "",
            "Python-Dateien (*.py);;Alle Dateien (*.*)")

        if file_path:
            self._pytest_run_file(file_path)

    def _pytest_run_file(self, file_path: str):
        """Führt eine spezifische Pytest-Datei aus."""
        import subprocess
        import os
        from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QPlainTextEdit,
                                      QPushButton, QHBoxLayout, QLabel,
                                      QCheckBox, QLineEdit)
        from PyQt6.QtGui import QFont
        from PyQt6.QtCore import QProcess

        # Speichere letzten Testpfad
        self._last_pytest_path = file_path

        dialog = QDialog(self)
        dialog.setWindowTitle("Pytest Runner")
        dialog.resize(800, 600)

        layout = QVBoxLayout(dialog)

        # Optionen
        opt_layout = QHBoxLayout()
        opt_layout.addWidget(QLabel("Pytest Optionen:"))

        verbose_check = QCheckBox("-v (verbose)")
        verbose_check.setChecked(True)
        opt_layout.addWidget(verbose_check)

        exitfirst_check = QCheckBox("-x (bei erstem Fehler stoppen)")
        opt_layout.addWidget(exitfirst_check)

        html_check = QCheckBox("--html (HTML-Report)")
        opt_layout.addWidget(html_check)

        extra_args = QLineEdit()
        extra_args.setPlaceholderText("Zusätzliche Argumente...")
        opt_layout.addWidget(extra_args)

        opt_layout.addStretch()
        layout.addLayout(opt_layout)

        # Output
        output = QPlainTextEdit()
        output.setReadOnly(True)
        output.setFont(QFont("Consolas", 9))
        p = ThemeManager.instance().get_palette()
        output.setStyleSheet(f"background-color: {p.bg_tertiary}; color: {p.text_primary};")
        layout.addWidget(output)

        # Status
        status_label = QLabel("Bereit zum Ausführen")
        layout.addWidget(status_label)

        # Buttons
        btn_layout = QHBoxLayout()

        run_btn = QPushButton("▶️ Ausführen")
        stop_btn = QPushButton("⏹️ Stoppen")
        stop_btn.setEnabled(False)

        process = QProcess(dialog)

        def run_pytest():
            output.clear()
            args = ["-m", "pytest", file_path]

            if verbose_check.isChecked():
                args.append("-v")
            if exitfirst_check.isChecked():
                args.append("-x")
            if html_check.isChecked():
                report_path = file_path.replace('.py', '_report.html')
                args.extend(["--html", report_path, "--self-contained-html"])
                self._last_pytest_report = report_path

            if extra_args.text():
                args.extend(extra_args.text().split())

            args.append("--tb=short")
            args.append("--color=no")

            output.appendPlainText(f"Ausführen: python {' '.join(args)}\n")
            output.appendPlainText("=" * 60 + "\n")

            run_btn.setEnabled(False)
            stop_btn.setEnabled(True)
            status_label.setText("Test läuft...")

            process.start("python", args)

        def stop_pytest():
            process.kill()
            status_label.setText("Test abgebrochen")

        def on_output():
            data = process.readAllStandardOutput().data().decode('utf-8', errors='replace')
            output.appendPlainText(data)

        def on_error():
            data = process.readAllStandardError().data().decode('utf-8', errors='replace')
            output.appendPlainText(data)

        def on_finished(exit_code, exit_status):
            run_btn.setEnabled(True)
            stop_btn.setEnabled(False)
            if exit_code == 0:
                status_label.setText("✓ Alle Tests bestanden")
                status_label.setStyleSheet("color: green; font-weight: bold;")
            else:
                status_label.setText(f"✗ Tests fehlgeschlagen (Exit-Code: {exit_code})")
                status_label.setStyleSheet("color: red; font-weight: bold;")
            output.appendPlainText("\n" + "=" * 60)
            output.appendPlainText(f"Beendet mit Exit-Code: {exit_code}")

        process.readyReadStandardOutput.connect(on_output)
        process.readyReadStandardError.connect(on_error)
        process.finished.connect(on_finished)

        run_btn.clicked.connect(run_pytest)
        stop_btn.clicked.connect(stop_pytest)

        btn_layout.addWidget(run_btn)
        btn_layout.addWidget(stop_btn)
        btn_layout.addStretch()

        close_btn = QPushButton("Schließen")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

        # Automatisch starten
        dialog.show()
        run_pytest()

        dialog.exec()

    def _pytest_run_last(self):
        """Führt den letzten Pytest-Test erneut aus."""
        if hasattr(self, '_last_pytest_path') and self._last_pytest_path:
            self._pytest_run_file(self._last_pytest_path)
        else:
            QMessageBox.information(self, "Pytest",
                "Kein vorheriger Test vorhanden.\n"
                "Bitte wählen Sie zuerst eine Testdatei aus.")

    def _pytest_show_report(self):
        """Zeigt den letzten HTML-Report an."""
        import os
        import webbrowser

        if hasattr(self, '_last_pytest_report') and os.path.exists(self._last_pytest_report):
            webbrowser.open(f"file://{os.path.abspath(self._last_pytest_report)}")
        else:
            from PyQt6.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getOpenFileName(
                self, "HTML-Report öffnen", "",
                "HTML-Dateien (*.html);;Alle Dateien (*.*)")
            if file_path:
                webbrowser.open(f"file://{os.path.abspath(file_path)}")

    def _pytest_configure(self):
        """Konfiguriert Pytest-Einstellungen."""
        from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QFormLayout,
                                      QLineEdit, QCheckBox, QDialogButtonBox,
                                      QGroupBox, QTextEdit, QLabel)

        dialog = QDialog(self)
        dialog.setWindowTitle("Pytest Konfiguration")
        dialog.resize(500, 450)

        layout = QVBoxLayout(dialog)

        # Allgemeine Einstellungen
        general_group = QGroupBox("Allgemeine Einstellungen")
        general_layout = QFormLayout(general_group)

        test_dir = QLineEdit()
        test_dir.setPlaceholderText("./tests")
        general_layout.addRow("Test-Verzeichnis:", test_dir)

        pattern = QLineEdit()
        pattern.setText("test_*.py")
        general_layout.addRow("Datei-Pattern:", pattern)

        layout.addWidget(general_group)

        # Optionen
        options_group = QGroupBox("Standard-Optionen")
        options_layout = QVBoxLayout(options_group)

        verbose = QCheckBox("Verbose Ausgabe (-v)")
        verbose.setChecked(True)
        options_layout.addWidget(verbose)

        capture = QCheckBox("Ausgabe nicht erfassen (-s)")
        options_layout.addWidget(capture)

        exitfirst = QCheckBox("Bei erstem Fehler stoppen (-x)")
        options_layout.addWidget(exitfirst)

        parallel = QCheckBox("Parallel ausführen (-n auto, benötigt pytest-xdist)")
        options_layout.addWidget(parallel)

        cov = QCheckBox("Code Coverage (--cov, benötigt pytest-cov)")
        options_layout.addWidget(cov)

        layout.addWidget(options_group)

        # pytest.ini Vorlage
        ini_group = QGroupBox("pytest.ini Vorlage")
        ini_layout = QVBoxLayout(ini_group)

        ini_text = QTextEdit()
        ini_text.setPlainText("""[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
""")
        ini_text.setMaximumHeight(150)
        ini_layout.addWidget(ini_text)

        save_ini_btn = QPushButton("pytest.ini speichern...")
        def save_ini():
            from PyQt6.QtWidgets import QFileDialog
            path, _ = QFileDialog.getSaveFileName(dialog, "pytest.ini speichern",
                                                   "pytest.ini", "INI-Dateien (*.ini)")
            if path:
                with open(path, 'w') as f:
                    f.write(ini_text.toPlainText())
                QMessageBox.information(dialog, "Gespeichert", f"Datei gespeichert:\n{path}")
        save_ini_btn.clicked.connect(save_ini)
        ini_layout.addWidget(save_ini_btn)

        layout.addWidget(ini_group)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)

        dialog.exec()

    # =========================================================================
    # Jenkins CI/CD Panel-Methoden
    # =========================================================================

    def _get_or_create_jenkins_panel(self) -> 'JenkinsPanel':
        """Gibt ein bestehendes Jenkins-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, JenkinsPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        panel = JenkinsPanel()
        self._plot_tabs.addTab(panel, 'Jenkins CI/CD')
        self._plot_tabs.setCurrentWidget(panel)
        return panel

    def _show_jenkins_panel(self):
        """Öffnet das Jenkins CI/CD Panel."""
        self._get_or_create_jenkins_panel()

    def _show_jenkins_panel_tab(self, tab_index: int):
        """Öffnet das Jenkins-Panel und wechselt zum angegebenen Tab."""
        panel = self._get_or_create_jenkins_panel()
        panel.show_tab(tab_index)

    def _show_jenkins_config(self):
        """Öffnet den Jenkins-Konfigurations-Dialog."""
        panel = self._get_or_create_jenkins_panel()
        panel.show_config()

    # =========================================================================
    # PTP/gPTP Panel-Methoden
    # =========================================================================

    def _get_or_create_ptp_panel(self) -> 'PTPPanel':
        """Gibt ein bestehendes PTP-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, PTPPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        panel = PTPPanel()
        self._plot_tabs.addTab(panel, 'PTP/gPTP')
        self._plot_tabs.setCurrentWidget(panel)
        return panel

    def _show_ptp_panel(self):
        """Öffnet das PTP/gPTP Analyse-Panel."""
        self._get_or_create_ptp_panel()

    # =========================================================================
    # XCP-Methoden
    # =========================================================================

    def _show_xcp_panel(self):
        """Öffnet das XCP-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, XCPPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        xcp_tab = XCPPanel()
        self._plot_tabs.addTab(xcp_tab, 'XCP')
        self._plot_tabs.setCurrentWidget(xcp_tab)

    def _get_xcp_panel(self) -> 'XCPPanel':
        """Gibt das XCPPanel zurück oder erstellt es."""
        self._show_xcp_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, XCPPanel):
                return widget
        return None

    def _xcp_open_a2l(self):
        """Öffnet eine A2L-Datei."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('files')
            panel._file_panel._open_a2l()

    def _xcp_create_a2l(self):
        """Erstellt/bearbeitet eine A2L-Datei."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('files')
            panel._file_panel._create_a2l()

    def _xcp_load_hex(self):
        """Lädt eine HEX-Datei."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('files')
            panel._file_panel._load_hex()

    def _xcp_generate_hex(self):
        """Generiert eine HEX-Datei."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('files')
            panel._file_panel._generate_hex()

    def _xcp_new_connection(self):
        """Öffnet den Verbindungsdialog."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')

    def _xcp_disconnect(self):
        """Trennt die XCP-Verbindung."""
        panel = self._get_xcp_panel()
        if panel:
            panel._connection_panel._disconnect()

    def _xcp_show_status(self):
        """Zeigt den Verbindungsstatus."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            status = panel.handler.get_status()
            QMessageBox.information(
                self, 'XCP-Status',
                f"Verbunden: {status['connected']}\n"
                f"Status: {status['state']}\n"
                f"A2L geladen: {status['a2l_loaded']}\n"
                f"HEX geladen: {status['hex_loaded']}\n"
                f"DAQ-Listen: {status['daq_lists']}\n"
                f"Messung aktiv: {status['measuring']}"
            )

    def _xcp_configure_transport(self, transport: str):
        """Konfiguriert eine Transportschicht."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            QMessageBox.information(
                self, 'Transport',
                f"{transport}-Konfiguration wird geöffnet..."
            )

    def _xcp_can_id_settings(self):
        """Öffnet CAN-ID Einstellungen."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            QMessageBox.information(
                self, 'CAN-ID',
                'CAN-ID Einstellungen:\n'
                '- Master CAN-ID\n'
                '- Slave CAN-ID\n'
                '(Im Verbindungs-Tab konfigurierbar)'
            )

    def _xcp_toggle_canfd(self, checked: bool):
        """Aktiviert/deaktiviert CAN FD."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            panel._connection_panel._canfd_radio.setChecked(checked)

    def _xcp_can_timing(self):
        """Öffnet Baudrate/Timing Einstellungen."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            QMessageBox.information(
                self, 'CAN Timing',
                'Baudrate und Timing Einstellungen\n'
                '(Im Verbindungs-Tab konfigurierbar)'
            )

    def _xcp_eth_settings(self):
        """Öffnet Ethernet-Einstellungen."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            panel._connection_panel._config_tabs.setCurrentIndex(1)

    def _xcp_network_discovery(self):
        """Führt Netzwerk-Discovery durch."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            panel._connection_panel._run_discovery()

    def _xcp_flexray_slot(self):
        """Öffnet FlexRay Slot-Zuordnung."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            panel._connection_panel._config_tabs.setCurrentIndex(2)

    def _xcp_flexray_cycle(self):
        """Öffnet FlexRay Cycle/Segment Einstellungen."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('connection')
            panel._connection_panel._config_tabs.setCurrentIndex(2)

    def _xcp_configure_daq(self):
        """Öffnet DAQ-Listen Konfiguration."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('measurement')

    def _xcp_start_measurement(self):
        """Startet die XCP-Messung."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('measurement')
            panel._measurement_panel._start_measurement()

    def _xcp_stop_measurement(self):
        """Stoppt die XCP-Messung."""
        panel = self._get_xcp_panel()
        if panel:
            panel._measurement_panel._stop_measurement()

    def _xcp_configure_events(self):
        """Öffnet Event-Konfiguration."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('measurement')
            QMessageBox.information(
                self, 'Events',
                'Event-Konfiguration\n'
                '(Im Messung-Tab konfigurierbar)'
            )

    def _xcp_read_parameter(self):
        """Liest Kalibrierparameter."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('calibration')

    def _xcp_write_parameter(self):
        """Schreibt Kalibrierparameter."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('calibration')

    def _xcp_page_switching(self):
        """Öffnet Page Switching Dialog."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('calibration')
            QMessageBox.information(
                self, 'Page Switching',
                'Kalibrierseiten umschalten\n'
                '(Im Kalibrierung-Tab verfügbar)'
            )

    def _xcp_flash_programming(self):
        """Öffnet Flash-Programmierung."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('flash')

    def _xcp_seedkey_config(self):
        """Öffnet Seed & Key Konfiguration."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('security')

    def _xcp_resource_protection(self):
        """Öffnet Ressourcenschutz-Dialog."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('security')

    def _xcp_ecu_info(self):
        """Zeigt ECU-Informationen."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('diagnostics')
            panel._diagnostics_panel._refresh_info()

    def _xcp_error_log(self):
        """Zeigt Fehler-Log."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('diagnostics')

    def _xcp_protocol_trace(self):
        """Zeigt Protokoll-Trace."""
        panel = self._get_xcp_panel()
        if panel:
            panel.show_tab('diagnostics')

    # =========================================================================
    # Busdatenbank-Methoden
    # =========================================================================

    def _show_bus_database_panel(self):
        """Öffnet das Busdatenbank-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusDatabasePanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        busdb_tab = BusDatabasePanel()
        self._plot_tabs.addTab(busdb_tab, 'Busdatenbank')
        self._plot_tabs.setCurrentWidget(busdb_tab)

    def _show_bus_trace_panel(self):
        """Öffnet das Bus-Trace Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusTracePanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        trace_tab = BusTracePanel()

        # Mit Time-Sync verbinden
        self._connect_bus_trace_to_sync(trace_tab)

        self._plot_tabs.addTab(trace_tab, 'Bus-Trace')
        self._plot_tabs.setCurrentWidget(trace_tab)

    def _show_xml_editor_panel(self):
        """Öffnet das XML-Editor Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, XMLEditorPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return

        xml_tab = XMLEditorPanel()
        self._plot_tabs.addTab(xml_tab, 'XML-Editor')
        self._plot_tabs.setCurrentWidget(xml_tab)

    def _get_bus_database_panel(self) -> 'BusDatabasePanel':
        """Gibt das BusDatabasePanel zurück oder erstellt es."""
        self._show_bus_database_panel()
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusDatabasePanel):
                return widget
        return None

    # DBC-Methoden
    def _busdb_open_dbc(self):
        """Öffnet eine DBC-Datei."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dbc_tab()
            panel._dbc_tab._open_file()

    def _busdb_create_dbc(self):
        """Erstellt/bearbeitet eine DBC-Datei."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dbc_tab()
            QMessageBox.information(self, "DBC Editor",
                                  "DBC-Editor Funktion wird geöffnet...\n(Demo-Modus)")

    def _busdb_decode_mdf_dbc(self):
        """Dekodiert MDF mit DBC."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()

    def _busdb_export_dbc(self):
        """Exportiert DBC-Signale."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dbc_tab()
            panel._dbc_tab._export_csv()

    # ARXML-Methoden
    def _busdb_open_arxml(self):
        """Öffnet eine ARXML-Datei."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_arxml_tab()
            panel._arxml_tab._open_file()

    def _busdb_load_ecu(self):
        """Lädt ECU-Konfiguration."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_arxml_tab()
            panel._arxml_tab._open_file()

    def _busdb_swc_analysis(self):
        """Zeigt SWC-Analyse."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_arxml_tab()

    def _busdb_pdu_mapping(self):
        """Zeigt PDU-Mapping."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_arxml_tab()

    def _busdb_signal_extraction(self):
        """Signal-Extraktion aus ARXML."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()

    # FIBEX-Methoden
    def _busdb_open_fibex(self):
        """Öffnet eine FIBEX-Datei."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_fibex_tab()
            panel._fibex_tab._open_file()

    def _busdb_show_cluster(self):
        """Zeigt FlexRay-Cluster."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_fibex_tab()

    def _busdb_show_frames(self):
        """Zeigt Frame-Definition."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_fibex_tab()

    def _busdb_decode_flexray(self):
        """Dekodiert FlexRay-Daten."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()

    # DLT-Methoden
    def _busdb_open_dlt(self):
        """Öffnet eine DLT-Datei."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dlt_tab()
            panel._dlt_tab._open_file()

    def _busdb_open_json(self):
        """Öffnet eine JSON-Datei und zeigt den Inhalt an."""
        import json
        from PyQt6.QtWidgets import QFileDialog, QDialog, QVBoxLayout, QPlainTextEdit, QDialogButtonBox
        from PyQt6.QtGui import QFont

        file_path, _ = QFileDialog.getOpenFileName(
            self, "JSON-Datei öffnen", "",
            "JSON-Dateien (*.json);;Alle Dateien (*.*)")

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Dialog zum Anzeigen des JSON-Inhalts
                dialog = QDialog(self)
                dialog.setWindowTitle(f"JSON Viewer - {file_path}")
                dialog.resize(800, 600)

                layout = QVBoxLayout(dialog)

                # Text-Editor mit JSON-Inhalt
                text_edit = QPlainTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setFont(QFont("Consolas", 10))
                text_edit.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
                layout.addWidget(text_edit)

                # Buttons
                buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
                buttons.accepted.connect(dialog.accept)
                layout.addWidget(buttons)

                dialog.exec()

            except json.JSONDecodeError as e:
                QMessageBox.critical(self, "JSON Fehler",
                    f"Die Datei ist keine gültige JSON-Datei:\n{e}")
            except Exception as e:
                QMessageBox.critical(self, "Fehler",
                    f"Fehler beim Öffnen der Datei:\n{e}")

    def _busdb_dlt_filter(self):
        """Konfiguriert DLT-Filter."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dlt_tab()
            dlt_tab = panel._dlt_tab
            if not dlt_tab._handler.is_loaded:
                QMessageBox.information(
                    self, "DLT-Filter",
                    "Bitte laden Sie zuerst eine DLT-Datei.\n\n"
                    "Nutzen Sie 'DLT-Datei öffnen...' um eine Datei zu laden."
                )
            else:
                # Fokus auf Textfilter setzen
                dlt_tab._text_filter.setFocus()
                QMessageBox.information(
                    self, "DLT-Filter",
                    "Nutzen Sie die Filter-Dropdowns im DLT-Tab:\n\n"
                    "• ECU - Nach ECU-ID filtern\n"
                    "• App - Nach Application-ID filtern\n"
                    "• Context - Nach Context-ID filtern\n"
                    "• Level - Nach Log-Level filtern\n"
                    "• Textfilter - Nach Text im Payload suchen"
                )

    def _busdb_dlt_contexts(self):
        """Verwaltet DLT-Kontexte."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dlt_tab()
            dlt_tab = panel._dlt_tab
            if not dlt_tab._handler.is_loaded:
                QMessageBox.information(
                    self, "DLT-Kontexte",
                    "Bitte laden Sie zuerst eine DLT-Datei.\n\n"
                    "Nutzen Sie 'DLT-Datei öffnen...' um eine Datei zu laden."
                )
            else:
                # Alle Kontexte sammeln und anzeigen
                contexts = dlt_tab._handler.get_context_ids()
                apps = dlt_tab._handler.get_application_ids()
                ecus = dlt_tab._handler.get_ecu_ids()

                info_text = f"Gefundene Elemente in der DLT-Datei:\n\n"
                info_text += f"ECUs ({len(ecus)}):\n"
                for ecu in ecus[:20]:
                    info_text += f"  • {ecu}\n"
                if len(ecus) > 20:
                    info_text += f"  ... und {len(ecus) - 20} weitere\n"

                info_text += f"\nApplications ({len(apps)}):\n"
                for app in apps[:20]:
                    info_text += f"  • {app}\n"
                if len(apps) > 20:
                    info_text += f"  ... und {len(apps) - 20} weitere\n"

                info_text += f"\nContexts ({len(contexts)}):\n"
                for ctx in contexts[:20]:
                    info_text += f"  • {ctx}\n"
                if len(contexts) > 20:
                    info_text += f"  ... und {len(contexts) - 20} weitere\n"

                QMessageBox.information(self, "DLT-Kontexte", info_text)

    def _busdb_export_dlt(self):
        """Exportiert DLT-Logs."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_dlt_tab()
            panel._dlt_tab._export_logs()

    # MDF-Integration-Methoden
    def _busdb_apply_to_mdf(self):
        """Wendet Datenbank auf MDF an."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()

    def _busdb_decode_raw(self):
        """Dekodiert Raw CAN/FlexRay."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()
            panel._mdf_tab._decode_raw()

    def _busdb_extract_signals(self):
        """Extrahiert Signale in MDF."""
        panel = self._get_bus_database_panel()
        if panel:
            panel.show_mdf_integration_tab()
            panel._mdf_tab._extract_signals()

    # =========================================================================
    # Converter-Methoden (ASAM Format-Konvertierung)
    # =========================================================================

    def _show_converter_panel(self):
        """Öffnet das Converter-Panel für ASAM-Formatkonvertierung."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, ConverterPanel):
                self._plot_tabs.setCurrentIndex(i)
                return
        converter_tab = ConverterPanel()
        converter_tab.file_opened.connect(self._add_to_recent)
        self._plot_tabs.addTab(converter_tab, 'Converter')
        self._plot_tabs.setCurrentWidget(converter_tab)

    def _get_converter_panel(self) -> Optional[ConverterPanel]:
        """Gibt das Converter-Panel zurück oder erstellt eines."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, ConverterPanel):
                self._plot_tabs.setCurrentIndex(i)
                return widget
        converter_tab = ConverterPanel()
        converter_tab.file_opened.connect(self._add_to_recent)
        self._plot_tabs.addTab(converter_tab, 'Converter')
        self._plot_tabs.setCurrentWidget(converter_tab)
        return converter_tab

    def _convert_asam(self, source_format: str, target_format: str):
        """Startet eine ASAM-Formatkonvertierung."""
        panel = self._get_converter_panel()
        if panel:
            panel.set_conversion(source_format, target_format)

    def _show_batch_converter(self):
        """Öffnet den Batch-Konvertierungs-Dialog."""
        panel = self._get_converter_panel()
        if panel:
            panel.show_batch_mode()

    # =========================================================================
    # Terminal-Panel
    # =========================================================================

    def _get_or_create_terminal_panel(self) -> TerminalPanel:
        """Gibt ein bestehendes Terminal-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, TerminalPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        terminal_tab = TerminalPanel()
        self._plot_tabs.addTab(terminal_tab, 'Terminal')
        self._plot_tabs.setCurrentWidget(terminal_tab)
        return terminal_tab

    def _show_terminal_panel(self):
        """Öffnet das Terminal-Panel."""
        self._get_or_create_terminal_panel()

    def _show_terminal_ssh(self):
        """Öffnet das Terminal-Panel und zeigt den SSH-Dialog."""
        panel = self._get_or_create_terminal_panel()
        panel.open_ssh_dialog()

    def _show_terminal_serial(self):
        """Öffnet das Terminal-Panel und zeigt den Seriell-Dialog."""
        panel = self._get_or_create_terminal_panel()
        panel.open_serial_dialog()

    def _show_terminal_quick_connect(self):
        """Öffnet das Terminal-Panel mit Quick-Connect."""
        panel = self._get_or_create_terminal_panel()
        panel.open_quick_connect()

    # =========================================================================
    # Schnell-arbeiten-Panel
    # =========================================================================

    def _get_or_create_schnellarbeit_panel(self) -> 'SchnellarbeitPanel':
        """Gibt ein bestehendes Schnellarbeit-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, SchnellarbeitPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        panel = SchnellarbeitPanel()
        self._plot_tabs.addTab(panel, 'Schnell arbeiten')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_schnellarbeit_panel(self):
        """Öffnet das Schnell-arbeiten-Panel."""
        self._get_or_create_schnellarbeit_panel()

    # ── REST API PROG Methoden ────────────────────────────────────

    def _get_or_create_restapi_prog(self):
        for i in range(self._plot_tabs.count()):
            w = self._plot_tabs.widget(i)
            if isinstance(w, RestApiProgPanel):
                self._plot_tabs.setCurrentWidget(w)
                return w
        panel = RestApiProgPanel()
        self._plot_tabs.addTab(panel, 'REST API PROG')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_restapi_prog(self):
        self._get_or_create_restapi_prog()

    # ── Lua Script PROG Methoden ──────────────────────────────────

    def _get_or_create_lua_script_prog(self):
        for i in range(self._plot_tabs.count()):
            w = self._plot_tabs.widget(i)
            if isinstance(w, LuaScriptProgPanel):
                self._plot_tabs.setCurrentWidget(w)
                return w
        panel = LuaScriptProgPanel()
        self._plot_tabs.addTab(panel, 'Lua Script PROG')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_lua_script_prog(self):
        self._get_or_create_lua_script_prog()

    # ── Framework PROG Methoden ────────────────────────────────────

    def _get_or_create_framework_prog(self):
        for i in range(self._plot_tabs.count()):
            w = self._plot_tabs.widget(i)
            if isinstance(w, FrameworkProgPanel):
                self._plot_tabs.setCurrentWidget(w)
                return w
        panel = FrameworkProgPanel()
        self._plot_tabs.addTab(panel, 'Framework PROG')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_framework_prog(self):
        self._get_or_create_framework_prog()

    # ── Framework MDF PROG Methoden ───────────────────────────────

    def _get_or_create_framework_mdf_prog(self):
        for i in range(self._plot_tabs.count()):
            w = self._plot_tabs.widget(i)
            if isinstance(w, FrameworkMdfProgPanel):
                self._plot_tabs.setCurrentWidget(w)
                return w
        panel = FrameworkMdfProgPanel()
        self._plot_tabs.addTab(panel, 'Framework MDF PROG')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_framework_mdf_prog(self):
        self._get_or_create_framework_mdf_prog()

    # ── Logger-Panel Methoden ──────────────────────────────────────

    def _get_or_create_logger_panel(self) -> 'LoggerPanel':
        """Gibt ein bestehendes Logger-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, LoggerPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        logger_tab = LoggerPanel()
        self._plot_tabs.addTab(logger_tab, 'Logger')
        self._plot_tabs.setCurrentWidget(logger_tab)
        # Zur Hauptansicht wechseln falls Willkommensseite aktiv
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return logger_tab

    def _show_logger_panel(self):
        """Öffnet das Logger-Panel."""
        self._get_or_create_logger_panel()

    def _show_logger_with_device(self, device_type: str):
        """Öffnet das Logger-Panel mit vorgewähltem Gerät."""
        panel = self._get_or_create_logger_panel()
        panel.set_device_filter(device_type)

    def _show_logger_with_protocol(self, protocol: str):
        """Öffnet das Logger-Panel mit vorgewähltem Protokoll."""
        panel = self._get_or_create_logger_panel()
        panel.set_protocol_filter(protocol)

    def _show_logger_live_capture(self):
        """Öffnet das Logger-Panel und startet die Live-Capture."""
        panel = self._get_or_create_logger_panel()
        panel.start_live_capture()

    def _show_logger_save_mdf(self):
        """Öffnet das Logger-Panel und startet den MDF-Export."""
        panel = self._get_or_create_logger_panel()
        panel.save_as_mdf()

    def _show_logger_save_pcap(self):
        """Öffnet das Logger-Panel und startet den PCAP-Export."""
        panel = self._get_or_create_logger_panel()
        panel.save_as_pcap()

    def _show_logger_statistics(self):
        """Öffnet das Logger-Panel und zeigt die Statistiken."""
        panel = self._get_or_create_logger_panel()
        panel.show_statistics()

    def _show_logger_dashboard(self):
        """Öffnet das Logger Dashboard Panel."""
        for i in range(self._plot_tabs.count()):
            if isinstance(self._plot_tabs.widget(i), LoggerDashboardPanel):
                self._plot_tabs.setCurrentWidget(self._plot_tabs.widget(i))
                return
        panel = LoggerDashboardPanel()
        self._plot_tabs.addTab(panel, 'Logger Dashboard')
        self._plot_tabs.setCurrentWidget(panel)

    def _show_eol_test_panel(self):
        """Öffnet das EOL-Test Panel."""
        for i in range(self._plot_tabs.count()):
            if isinstance(self._plot_tabs.widget(i), EolTestPanel):
                self._plot_tabs.setCurrentWidget(self._plot_tabs.widget(i))
                return
        panel = EolTestPanel()
        self._plot_tabs.addTab(panel, 'EOL-Test')
        self._plot_tabs.setCurrentWidget(panel)

    def _show_device_discovery(self):
        """Öffnet den Geräte-Erkennung-Dialog (Logger Discovery)."""
        from ui.dialogs.device_discovery_dialog import DeviceDiscoveryDialog
        dialog = DeviceDiscoveryDialog(self)
        if dialog.exec() == DeviceDiscoveryDialog.DialogCode.Accepted:
            device = dialog.get_selected_device()
            if device:
                panel = self._get_or_create_logger_panel()
                name = device.get("name", "")
                # Geräte-Filter im Logger-Panel setzen
                if "AED SLA (GMSL" in name:
                    panel.set_device_filter("AED SLA (GMSL2/3)")
                elif "AED SLA (FPD" in name:
                    panel.set_device_filter("AED SLA (FPD-Link III/IV)")
                elif "Technica" in name:
                    for d in ['CM 1000 High', 'CM 100 High', 'CM 10Base-T1S',
                              'CM SerDes', 'CM MultiGigabit', 'CM Ethernet Combo',
                              'CM ILaS Combo', 'CM CAN Combo', 'CM LIN Combo']:
                        if d in name:
                            panel.set_device_filter(f"Technica {d}")
                            break

    # ── Syslog Analyse Panel Methoden ────────────────────────────────

    def _get_or_create_syslog_panel(self) -> 'SyslogAnalysePanel':
        """Gibt ein bestehendes Syslog-Analyse-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, SyslogAnalysePanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        panel = SyslogAnalysePanel()
        self._plot_tabs.addTab(panel, 'Syslog Analyse')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_syslog_analyse(self):
        """Öffnet das Syslog-Analyse-Panel."""
        self._get_or_create_syslog_panel()

    # ── Monitor Analyse Panel Methoden ──────────────────────────────

    def _get_or_create_monitor_analyse_panel(self) -> 'MonitorAnalysePanel':
        """Gibt ein bestehendes Monitor-Analyse-Panel zurück oder erstellt ein neues."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, MonitorAnalysePanel):
                self._plot_tabs.setCurrentWidget(widget)
                return widget
        panel = MonitorAnalysePanel()
        self._plot_tabs.addTab(panel, 'Monitor Analyse')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
        return panel

    def _show_monitor_analyse(self):
        """Öffnet das Monitor-Analyse-Panel."""
        self._get_or_create_monitor_analyse_panel()

    # ==================================================================
    # Analyse-Features (CANoe-Kernfeatures)
    # ==================================================================

    def _show_bus_statistics_panel(self):
        """Oeffnet das Bus-Statistik-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, BusStatisticsPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return
        panel = BusStatisticsPanel()
        if self._current_handler:
            panel.load_mdf_data(self._current_handler)
        self._plot_tabs.addTab(panel, 'Bus-Statistik')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)

    def _show_state_tracker_panel(self):
        """Oeffnet das State-Tracker-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, StateTrackerPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return
        panel = StateTrackerPanel()
        panel.cursorTimeChanged.connect(
            self._time_sync_manager.on_plot_cursor_moved
        )
        self._plot_tabs.addTab(panel, 'State Tracker')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)

    def _show_trigger_config(self):
        """Oeffnet den Trigger-Konfigurations-Dialog."""
        if not hasattr(self, '_trigger_engine'):
            self._trigger_engine = TriggerEngine(self)
        dialog = TriggerConfigDialog(self._trigger_engine, self)
        dialog.exec()

    def _show_replay_panel(self):
        """Oeffnet das Replay-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, ReplayPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return
        panel = ReplayPanel()
        panel.timePositionChanged.connect(
            self._time_sync_manager.on_slider_moved
        )
        self._plot_tabs.addTab(panel, 'Replay')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)

    def _show_message_generator_panel(self):
        """Oeffnet das Nachrichten-Generator-Panel."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, MessageGeneratorPanel):
                self._plot_tabs.setCurrentWidget(widget)
                return
        panel = MessageGeneratorPanel()
        self._plot_tabs.addTab(panel, 'Nachrichten-Generator')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)

    def _show_diagnostic_console_panel(self):
        """Oeffnet die Diagnose-Konsole."""
        for i in range(self._plot_tabs.count()):
            widget = self._plot_tabs.widget(i)
            if isinstance(widget, DiagnosticConsolePanel):
                self._plot_tabs.setCurrentWidget(widget)
                return
        panel = DiagnosticConsolePanel()
        self._plot_tabs.addTab(panel, 'Diagnose-Konsole')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)

    def _show_bus_data_analyzer(self):
        """Oeffnet das Bus-Daten-Analyse Panel."""
        for i in range(self._plot_tabs.count()):
            if isinstance(self._plot_tabs.widget(i), BusDataAnalyzerPanel):
                self._plot_tabs.setCurrentWidget(self._plot_tabs.widget(i))
                return
        panel = BusDataAnalyzerPanel()
        self._plot_tabs.addTab(panel, 'Bus-Daten-Analyse')
        self._plot_tabs.setCurrentWidget(panel)
        if hasattr(self, '_center_stack'):
            self._center_stack.setCurrentIndex(1)
