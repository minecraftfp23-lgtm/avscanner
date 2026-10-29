import sys
import json
import subprocess
import threading
import urllib.request
import urllib.error
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal, QSize
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QMessageBox, QStyle, QFrame
)
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFont, QIcon, QColor

# Path to Rust CLI binary
SCANNER_PATH = Path(__file__).parent / "bin" / "av-scan.exe"

# GitHub repo for updates
GITHUB_REPO = "yourusername/avscanner"
CURRENT_VERSION = "0.1.0"


@dataclass
class ScanResult:
    path: str
    hash: str
    verdict: str


@dataclass
class QuarantineItem:
    original_path: str
    quarantine_path: str
    hash: str
    verdict: str
    timestamp: str


class ScanWorker(QThread):
    progress = Signal(int, int, str)  # current, total, current_file
    finished = Signal(list)  # List[ScanResult]
    error = Signal(str)

    def __init__(self, paths: List[str], vt_key: Optional[str] = None):
        super().__init__()
        self.paths = paths
        self.vt_key = vt_key

    def run(self):
        try:
            all_results = []
            for i, path in enumerate(self.paths):
                p = Path(path)
                if p.is_file():
                    results = self.scan_single(p)
                    all_results.extend(results)
                    self.progress.emit(i + 1, len(self.paths), p.name)
                elif p.is_dir():
                    results = self.scan_dir(p)
                    all_results.extend(results)
                    self.progress.emit(i + 1, len(self.paths), p.name)

            self.finished.emit(all_results)
        except Exception as e:
            self.error.emit(str(e))

    def scan_single(self, path: Path) -> List[ScanResult]:
        cmd = [str(SCANNER_PATH), "file", str(path)]
        if self.vt_key:
            cmd.extend(["-k", self.vt_key])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return [ScanResult(str(path), "", f"error: {result.stderr}")]

        try:
            data = json.loads(result.stdout)
            return [ScanResult(**item) for item in data]
        except json.JSONDecodeError:
            return [ScanResult(str(path), "", f"error: invalid JSON")]

    def scan_dir(self, path: Path) -> List[ScanResult]:
        cmd = [str(SCANNER_PATH), "dir", str(path)]
        if self.vt_key:
            cmd.extend(["-k", self.vt_key])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return [ScanResult(str(path), "", f"error: {result.stderr}")]

        try:
            data = json.loads(result.stdout)
            return [ScanResult(**item) for item in data]
        except json.JSONDecodeError:
            return [ScanResult(str(path), "", f"error: invalid JSON")]


class DropZone(QFrame):
    file_dropped = Signal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setMinimumHeight(200)
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a3a3a;
                border-radius: 12px;
                background: #1e1e1e;
            }
            DropZone:hover {
                border-color: #4a90d9;
                background: #252525;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_label = QLabel("📁")
        icon_label.setFont(QFont("Segoe UI Emoji", 48))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        text_label = QLabel("Перетащите файлы или папки сюда\nили нажмите для выбора")
        text_label.setFont(QFont("Segoe UI", 12))
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text_label.setStyleSheet("color: #aaa;")

        layout.addWidget(icon_label)
        layout.addWidget(text_label)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("""
                DropZone {
                    border: 2px dashed #4a90d9;
                    border-radius: 12px;
                    background: #2a3a4a;
                }
            """)

    def dragLeaveEvent(self, event):
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a3a3a;
                border-radius: 12px;
                background: #1e1e1e;
            }
            DropZone:hover {
                border-color: #4a90d9;
                background: #252525;
            }
        """)

    def dropEvent(self, event: QDropEvent):
        self.dragLeaveEvent(event)
        urls = event.mimeData().urls()
        paths = [url.toLocalFile() for url in urls]
        if paths:
            self.file_dropped.emit(paths)


class VerdictWidget(QTableWidgetItem):
    COLORS = {
        "clean": QColor("#22c55e"),
        "malicious": QColor("#ef4444"),
        "suspicious": QColor("#f59e0b"),
        "unknown": QColor("#9ca3af"),
        "error": QColor("#ec4899"),
    }

    def __init__(self, verdict: str):
        super().__init__(verdict.capitalize())
        self.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setForeground(QColor("#ffffff"))
        color = self.COLORS.get(verdict.lower(), QColor("#9ca3af"))
        self.setBackground(color)
        self.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AvScanner")
        self.setMinimumSize(1000, 700)
        self.resize(1000, 700)

        # Dark theme
        self.setStyleSheet("""
            QMainWindow { background: #121212; }
            QLabel { color: #e0e0e0; }
            QPushButton {
                background: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
            }
            QPushButton:hover { background: #3a3a3a; }
            QPushButton:pressed { background: #4a90d9; }
            QPushButton:disabled { background: #1a1a1a; color: #666; }
            QProgressBar {
                border: none;
                border-radius: 4px;
                background: #1e1e1e;
                text-align: center;
                color: #e0e0e0;
                font-size: 12px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4a90d9, stop:1 #6ec6ff);
                border-radius: 4px;
            }
            QTableWidget {
                background: #1e1e1e;
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                gridline-color: #3a3a3a;
                color: #e0e0e0;
                font-size: 12px;
            }
            QHeaderView::section {
                background: #252525;
                border: none;
                border-bottom: 1px solid #3a3a3a;
                padding: 8px;
                color: #aaa;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background: #3a3a3a; }
        """)

        self.results: List[ScanResult] = []
        self.quarantine_items: List[QuarantineItem] = []
        self.worker: Optional[ScanWorker] = None

        # Quarantine directory
        self.quarantine_dir = Path.home() / ".avscanner" / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Update check
        self.update_available = False
        self.latest_version = None

        self.setup_ui()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header
        header = QHBoxLayout()
        title = QLabel("AvScanner")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        header.addWidget(title)
        header.addStretch()

        self.scan_folder_btn = QPushButton("📂 Сканировать папку")
        self.scan_folder_btn.clicked.connect(self.select_folder)
        header.addWidget(self.scan_folder_btn)

        self.vt_key_btn = QPushButton("🔑 VirusTotal API")
        self.vt_key_btn.clicked.connect(self.set_vt_key)
        header.addWidget(self.vt_key_btn)

        layout.addLayout(header)

        # Drop zone
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self.start_scan)
        layout.addWidget(self.drop_zone)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #888; font-size: 12px;")
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Файл", "SHA256", "Вердикт"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setVisible(False)
        layout.addWidget(self.table)

        # Empty state
        self.empty_label = QLabel("Файлы не выбраны")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet("color: #666; font-size: 14px; padding: 40px;")
        layout.addWidget(self.empty_label)

        self.vt_key: Optional[str] = None

        # Load existing quarantine log
        self.load_quarantine_log()

    def load_quarantine_log(self):
        """Load quarantine log from JSON"""
        import json
        log_file = self.quarantine_dir / "quarantine_log.json"
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    self.quarantine_items.append(QuarantineItem(**item))
            except Exception:
                pass

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для сканирования")
        if folder:
            self.start_scan([folder])

    def set_vt_key(self):
        from PySide6.QtWidgets import QInputDialog
        key, ok = QInputDialog.getText(self, "VirusTotal API Key", "Введите API ключ:")
        if ok and key:
            self.vt_key = key.strip()
            QMessageBox.information(self, "OK", "API ключ сохранён")

    def start_scan(self, paths: List[str]):
        if self.worker and self.worker.isRunning():
            return

        # Verify scanner exists
        if not SCANNER_PATH.exists():
            QMessageBox.critical(self, "Ошибка", f"Сканер не найден: {SCANNER_PATH}\nПоложите av-scan.exe в папку bin/")
            return

        self.results = []
        self.table.setRowCount(0)
        self.table.setVisible(False)
        self.empty_label.setVisible(False)

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setVisible(True)
        self.progress_label.setText("Подготовка...")

        self.scan_folder_btn.setEnabled(False)
        self.vt_key_btn.setEnabled(False)
        self.drop_zone.setEnabled(False)

        self.worker = ScanWorker(paths, self.vt_key)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_progress(self, current: int, total: int, filename: str):
        percent = int((current / total) * 100)
        self.progress_bar.setValue(percent)
        self.progress_label.setText(f"Сканирование {current}/{total}: {filename}")

    def on_finished(self, results: List[ScanResult]):
        self.results = results
        self.populate_table()
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.scan_folder_btn.setEnabled(True)
        self.vt_key_btn.setEnabled(True)
        self.drop_zone.setEnabled(True)

    def on_error(self, error: str):
        QMessageBox.critical(self, "Ошибка сканирования", error)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.scan_folder_btn.setEnabled(True)
        self.vt_key_btn.setEnabled(True)
        self.drop_zone.setEnabled(True)

    def populate_table(self):
        self.table.setRowCount(len(self.results))
        for row, result in enumerate(self.results):
            # Path
            path_item = QTableWidgetItem(result.path)
            path_item.setToolTip(result.path)
            self.table.setItem(row, 0, path_item)

            # Hash
            hash_display = result.hash[:16] + "..." if len(result.hash) > 16 else result.hash
            hash_item = QTableWidgetItem(hash_display)
            hash_item.setToolTip(result.hash)
            self.table.setItem(row, 1, hash_item)

            # Verdict
            self.table.setItem(row, 2, VerdictWidget(result.verdict))

            # Quarantine button for malicious/suspicious
            if result.verdict.lower() in ("malicious", "suspicious"):
                quarantine_btn = QPushButton("🔒 Карантин")
                quarantine_btn.setStyleSheet("""
                    QPushButton {
                        background: #ef4444;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 4px 8px;
                        font-size: 11px;
                    }
                    QPushButton:hover { background: #dc2626; }
                """)
                quarantine_btn.clicked.connect(lambda checked, r=result: self.quarantine_file(r))
                self.table.setCellWidget(row, 2, quarantine_btn)

        self.table.setVisible(True)
        self.table.resizeColumnsToContents()

    def quarantine_file(self, result: ScanResult):
        """Move suspicious/malicious file to quarantine"""
        import shutil
        from datetime import datetime

        src = Path(result.path)
        if not src.exists():
            QMessageBox.warning(self, "Ошибка", "Файл не найден")
            return

        # Create unique quarantine filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{timestamp}_{src.name}.quarantine"
        dst = self.quarantine_dir / safe_name

        try:
            shutil.move(str(src), str(dst))
            # Create metadata file
            meta = QuarantineItem(
                original_path=str(src),
                quarantine_path=str(dst),
                hash=result.hash,
                verdict=result.verdict,
                timestamp=timestamp
            )
            self.quarantine_items.append(meta)
            self.save_quarantine_log()

            QMessageBox.information(self, "Карантин", f"Файл перемещен в карантин:\n{dst}")
            # Refresh table
            self.populate_table()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось переместить в карантин: {e}")

    def save_quarantine_log(self):
        """Save quarantine log to JSON"""
        import json
        log_file = self.quarantine_dir / "quarantine_log.json"
        data = [
            {
                "original_path": item.original_path,
                "quarantine_path": item.quarantine_path,
                "hash": item.hash,
                "verdict": item.verdict,
                "timestamp": item.timestamp
            }
            for item in self.quarantine_items
        ]
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def check_for_updates(self):
        """Check GitHub releases for updates"""
        import urllib.request
        import urllib.error
        import json

        def check():
            try:
                url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
                req = urllib.request.Request(url, headers={'User-Agent': 'AvScanner'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    latest = data.get('tag_name', '').lstrip('v')
                    if latest and self.version_tuple(latest) > self.version_tuple(CURRENT_VERSION):
                        self.update_available = True
                        self.latest_version = latest
                        self.show_update_notification(latest, data.get('html_url', ''))
            except Exception:
                pass

        threading.Thread(target=check, daemon=True).start()

    def version_tuple(self, version: str):
        """Convert version string to tuple for comparison"""
        try:
            return tuple(map(int, version.split('.')))
        except Exception:
            return (0, 0, 0)

    def show_update_notification(self, version: str, url: str):
        """Show update available notification"""
        from PySide6.QtWidgets import QMessageBox
        msg = QMessageBox(self)
        msg.setWindowTitle("Доступно обновление")
        msg.setText(f"Доступна новая версия {version} (текущая: {CURRENT_VERSION})")
        msg.setInformativeText("Хотите открыть страницу загрузки?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg.setDefaultButton(QMessageBox.StandardButton.Yes)
        if msg.exec() == QMessageBox.StandardButton.Yes:
            import webbrowser
            webbrowser.open(url)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.check_for_updates()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()