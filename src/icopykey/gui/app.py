"""Main GUI application entry point."""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("icopykey.gui")

try:
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import (
        QApplication,
        QDialog,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    msg = "PyQt5 is required for the GUI. Install with: pip install PyQt5"
    print(msg, file=sys.stderr)
    sys.exit(1)

from pathlib import Path

from icopykey.cli.card_ops import CardOperations
from icopykey.cli.config_manager import ConfigManager
from icopykey.cli.constants import DEFAULT_KEYS
from icopykey.cli.device import CopyKeyDevice, CopyKeyRemoteDevice
from icopykey.cli.library import LocalLibrary
from icopykey.cli.mifare_data import MifareCard


class ConsoleHandler(logging.Handler):
    """Redirect log records to a QPlainTextEdit."""

    def __init__(self, widget: QPlainTextEdit) -> None:
        super().__init__()
        self.widget = widget
        self.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.Record) -> None:
        msg = self.format(record)
        self.widget.appendPlainText(msg)


class MainWindow(QMainWindow):
    """Main icopykey GUI window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("icopykey — NFC Card Manager")
        self.resize(1024, 720)

        self.device: CopyKeyDevice | None = None
        self.library: LocalLibrary | None = None
        self.current_card: MifareCard | None = None

        self._init_config()
        self._init_ui()
        self._init_logging()

    # ── Initialisation ────────────────────────────────────────────

    def _init_config(self) -> None:
        cfg = ConfigManager().config
        data_dir = Path(cfg.paths.vault_dir)
        vault_pw = None  # interactive prompt
        self.library = LocalLibrary(data_dir, vault_password=vault_pw)

    def _init_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # ── Toolbar ──
        toolbar = QHBoxLayout()
        self.btn_connect = QPushButton("Connect Device")
        self.btn_connect.clicked.connect(self._on_connect)
        self.lbl_status = QLabel("Disconnected")
        self.lbl_status.setStyleSheet("color: gray;")

        toolbar.addWidget(self.btn_connect)
        toolbar.addWidget(self.lbl_status)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # ── Splitter: tabs + console ──
        splitter = QSplitter(Qt.Vertical)

        self.tabs = QTabWidget()
        self._init_card_tab()
        self._init_library_tab()
        self._init_keys_tab()
        splitter.addWidget(self.tabs)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)
        splitter.addWidget(self.console)
        splitter.setSizes([500, 200])

        layout.addWidget(splitter)

    def _init_card_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Operation buttons
        ops = QHBoxLayout()
        btn_read = QPushButton("Read Card")
        btn_read.clicked.connect(self._on_read_card)
        btn_decode = QPushButton("Decode Card")
        btn_decode.clicked.connect(self._on_decode_card)
        ops.addWidget(btn_read)
        ops.addWidget(btn_decode)
        ops.addStretch()
        layout.addLayout(ops)

        # Sector table
        self.sector_table = QTableWidget(0, 5)
        self.sector_table.setHorizontalHeaderLabels(["Sector", "Key A", "Key B", "Blocks", "Status"])
        layout.addWidget(self.sector_table)

        self.tabs.addTab(tab, "Card")

    def _init_library_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        ops = QHBoxLayout()
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._on_library_refresh)
        ops.addWidget(btn_refresh)
        ops.addStretch()
        layout.addLayout(ops)

        self.card_list = QListWidget()
        self.card_list.itemDoubleClicked.connect(self._on_card_selected)
        layout.addWidget(self.card_list)

        self.tabs.addTab(tab, "Library")

    def _init_keys_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        ops = QHBoxLayout()
        btn_add = QPushButton("Add Key")
        btn_add.clicked.connect(self._on_add_key)
        ops.addWidget(btn_add)
        ops.addStretch()
        layout.addLayout(ops)

        self.key_list = QListWidget()
        layout.addWidget(self.key_list)

        self.tabs.addTab(tab, "Keys")

    def _init_logging(self) -> None:
        handler = ConsoleHandler(self.console)
        logging.getLogger("copykey_cli").addHandler(handler)
        logging.getLogger("copykey_cli").setLevel(logging.INFO)
        logging.info("icopykey GUI started")

    # ── Device operations ─────────────────────────────────────────

    def _on_connect(self) -> None:
        if self.device and self.device.is_connected():
            self.device.disconnect()
            self.device = None
            self.btn_connect.setText("Connect Device")
            self.lbl_status.setText("Disconnected")
            self.lbl_status.setStyleSheet("color: gray;")
            return

        self.device = CopyKeyDevice()
        if self.device.connect():
            self.btn_connect.setText("Disconnect")
            self.lbl_status.setText(f"Connected: {self.device.product or 'X100'}")
            self.lbl_status.setStyleSheet("color: green;")
            logging.info("Device connected: %s %s", self.device.manufacturer, self.device.product)
        else:
            QMessageBox.warning(self, "Connection Failed", "Could not find a CopyKEY device.")

    def _on_read_card(self) -> None:
        if not self.device or not self.device.is_connected():
            QMessageBox.warning(self, "Not Connected", "Connect a device first.")
            return

        info = self.device.read_card_info()
        if not info:
            QMessageBox.warning(self, "No Card", "No card detected.")
            return

        uid_hex = info["uid"].hex().upper()
        logging.info("Card detected: UID=%s  Type=%s", uid_hex, info["card_type"])

    def _on_decode_card(self) -> None:
        if not self.device or not self.device.is_connected():
            QMessageBox.warning(self, "Not Connected", "Connect a device first.")
            return

        if not self.device.read_card_info():
            QMessageBox.warning(self, "No Card", "No card detected.")
            return

        ops = CardOperations(self.device, self.library)
        card = ops.decode_card(custom_keys=self.library.get_keys() if self.library else None)
        if not card:
            logging.error("Decode failed or all sectors locked.")
            return

        self.current_card = card
        self._populate_sector_table(card)
        logging.info("Decoded %d/%d sectors", sum(1 for s in card.sectors if s.is_decoded), card.num_sectors)

    def _populate_sector_table(self, card: MifareCard) -> None:
        self.sector_table.setRowCount(len(card.sectors))
        for i, sec in enumerate(card.sectors):
            self.sector_table.setItem(i, 0, QTableWidgetItem(str(sec.sector_index)))
            self.sector_table.setItem(i, 1, QTableWidgetItem(sec.key_a.hex().upper() if sec.key_a else "—"))
            self.sector_table.setItem(i, 2, QTableWidgetItem(sec.key_b.hex().upper() if sec.key_b else "—"))
            block_count = len(sec.blocks) if sec.blocks else 0
            self.sector_table.setItem(i, 3, QTableWidgetItem(str(block_count)))
            status = "Decoded" if sec.is_decoded else "Locked"
            self.sector_table.setItem(i, 4, QTableWidgetItem(status))

    # ── Library operations ─────────────────────────────────────────

    def _on_library_refresh(self) -> None:
        self.card_list.clear()
        if not self.library:
            return
        for card_meta in self.library.list_cards():
            text = f"{card_meta['name']}  |  {card_meta['uid']}  |  {card_meta['card_type']}"
            self.card_list.addItem(text)

    def _on_card_selected(self) -> None:
        row = self.card_list.currentRow()
        if row < 0 or not self.library:
            return
        cards = self.library.list_cards()
        if row >= len(cards):
            return
        full = self.library.get_card(cards[row]["id"])
        if full:
            self.current_card = MifareCard.from_dict(full)
            self._populate_sector_table(self.current_card)
            self.tabs.setCurrentIndex(0)

    def _on_add_key(self) -> None:
        from PyQt6.QtWidgets import QDialog, QLineEdit

        dialog = QDialog(self)
        dialog.setWindowTitle("Add Key")
        layout = QFormLayout(dialog)
        name_input = QLineEdit()
        key_input = QLineEdit()
        layout.addRow("Name:", name_input)
        layout.addRow("Key (hex):", key_input)

        buttons = QHBoxLayout()
        btn_ok = QPushButton("Add")
        btn_ok.clicked.connect(dialog.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dialog.reject)
        buttons.addWidget(btn_ok)
        buttons.addWidget(btn_cancel)
        layout.addRow(buttons)

        if dialog.exec() == QDialog.Accepted:
            name = name_input.text().strip()
            key_hex = key_input.text().strip().replace(" ", "").replace(":", "")
            if name and key_hex and self.library:
                try:
                    key = bytes.fromhex(key_hex)
                    if len(key) == 6:
                        self.library.add_key(name, key)
                        self._refresh_key_list()
                        logging.info("Added key: %s = %s", name, key.hex().upper())
                except ValueError:
                    QMessageBox.warning(self, "Invalid Key", "Key must be 12 hex characters (6 bytes).")

    def _refresh_key_list(self) -> None:
        self.key_list.clear()
        if self.library:
            for name, key in self.library.keys.items():
                self.key_list.addItem(f"{name}: {key.hex().upper()}")


def run_gui() -> None:
    """Launch the icopykey GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("icopykey")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
