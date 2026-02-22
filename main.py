"""
main.py — SIGHAX Simulator
Simulador del exploit del bootROM ARM9 de la 3DS.

Requirements: pip install PyQt6
"""

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QTabWidget, QLabel
)
from PyQt6.QtCore  import Qt, QThread, pyqtSignal
from PyQt6.QtGui   import QFont, QPalette, QColor

from styles        import MAIN_STYLE, C
from crypto_engine import SighaxEngine
from ui_verify     import VerifyWidget
from ui_exploit    import ExploitWidget


class EngineInitThread(QThread):
    done = pyqtSignal(object)
    def run(self):
        self.done.emit(SighaxEngine())


class HeaderBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        self.setStyleSheet(
            f"QWidget {{background:{C['bg2']};border-bottom:1px solid {C['border']};}}"
            f"QLabel {{background:transparent;border:none;}}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(8)

        logo = QLabel("SIGHAX")
        logo.setStyleSheet(
            f"color:{C['red']};font-size:22px;font-weight:bold;"
            f"font-family:'JetBrains Mono','Fira Code','Consolas',monospace;"
        )
        layout.addWidget(logo)

        slash = QLabel(" / ")
        slash.setStyleSheet(f"color:{C['text_dim']};font-size:16px;")
        layout.addWidget(slash)

        subtitle = QLabel("ARM9 Bootrom Exploit Simulator")
        subtitle.setStyleSheet(
            f"color:{C['text']};font-size:13px;"
            f"font-family:'JetBrains Mono','Fira Code','Consolas',monospace;"
        )
        layout.addWidget(subtitle)

        layout.addStretch()

        for text, color in [
            ("3DS",          C['blue']),
            ("RSA-2048",     C['purple']),
            ("PKCS#1 v1.5",  C['cyan']),
            ("ARM9 ring-1",  C['red']),
            ("SciresM 2017", C['text_dim']),
        ]:
            badge = QLabel(text)
            badge.setStyleSheet(
                f"color:{color};background:{C['bg3']};"
                f"border:1px solid {color};border-radius:4px;"
                f"padding:3px 8px;font-size:10px;font-weight:bold;"
            )
            layout.addWidget(badge)
            layout.addSpacing(4)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIGHAX Simulator — ARM9 Bootrom")
        self.resize(1300, 860)
        self.setMinimumSize(1050, 700)
        self._show_loading()
        self._init_thread = EngineInitThread()
        self._init_thread.done.connect(self._on_engine_ready)
        self._init_thread.start()

    def _show_loading(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel("SIGHAX Simulator")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"color:{C['red']};font-size:32px;font-weight:bold;"
            f"font-family:'JetBrains Mono','Consolas',monospace;"
        )
        l.addWidget(title)
        sub = QLabel("Iniciando motor criptográfico...")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(f"color:{C['text_dim']};font-size:14px;")
        l.addWidget(sub)
        self.setCentralWidget(w)

    def _on_engine_ready(self, engine: SighaxEngine):
        root     = QWidget()
        r_layout = QVBoxLayout(root)
        r_layout.setContentsMargins(0, 0, 0, 0)
        r_layout.setSpacing(0)

        r_layout.addWidget(HeaderBar())

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.addTab(VerifyWidget(engine),  "  ✓  Verificación Legítima  ")
        tabs.addTab(ExploitWidget(engine), "  ⚡  Exploit SIGHAX  ")
        tabs.tabBar().setTabTextColor(1, QColor(C['red']))

        r_layout.addWidget(tabs, 1)
        self.setCentralWidget(root)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SIGHAX Simulator")

    font = QFont("JetBrains Mono", 11)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,        QColor(C['bg']))
    palette.setColor(QPalette.ColorRole.WindowText,    QColor(C['text']))
    palette.setColor(QPalette.ColorRole.Base,          QColor(C['bg2']))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(C['bg3']))
    palette.setColor(QPalette.ColorRole.Text,          QColor(C['text']))
    palette.setColor(QPalette.ColorRole.Button,        QColor(C['bg3']))
    palette.setColor(QPalette.ColorRole.ButtonText,    QColor(C['text']))
    palette.setColor(QPalette.ColorRole.Highlight,     QColor(C['blue']))
    app.setPalette(palette)
    app.setStyleSheet(MAIN_STYLE)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()