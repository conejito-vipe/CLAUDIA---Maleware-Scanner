"""Startbildschirm (Ladefenster) im Stil des Microsoft-365-Startfensters, mit PySide6.

  Splash   rahmenloses Fenster mit abgerundeten Ecken und weichem Schatten: Chip, Minimieren/Schließen, Logo, Ladebalken, Statuszeile
  QtUi     Anschluss an den Launcher (gleiche Aufrufe wie die tkinter-Oberfläche: update, log, error, finished, mainloop)

PySide6 wird nur gebraucht, wenn dieses Fenster benutzt wird. Fehlt es, nimmt der Launcher die tkinter-Oberfläche (siehe launcher.py).
"""
from __future__ import annotations

import os
import sys
from typing import Any, Callable, Optional

from PySide6.QtCore import QEasingCurve, QObject, QPoint, QPropertyAnimation, Qt, Signal, Slot
from PySide6.QtGui import QColor, QFontMetrics, QIcon, QPixmap
from PySide6.QtWidgets import (QApplication, QFrame, QGraphicsDropShadowEffect, QHBoxLayout, QLabel, QMessageBox, QProgressBar,
                               QToolButton, QVBoxLayout, QWidget)

APP_NAME = "CLAUDIA"
LOGO_FILE = os.path.join("assets", "claudia_logo.png")   # Logo ohne Hintergrund, vollständig (nicht beschnitten)
BG = "#E7EDF0"                          # Fensterfarbe wie das Tool
INK = "#1B2A33"
GRAY = "#6B7B86"                        # Statustext, Prozentzahl
ACCENT = "#E96413"                      # Orange aus dem Logo
GROOVE = "#E8E8E8"
CLOSE_RED = "#E81123"
WIN_W, WIN_H = 765, 480                 # Breite 15 % kleiner als zuvor (900), Höhe 20 % kleiner als die ursprünglichen 600
SHADOW = 28
RADIUS = 8
FONT = "Segoe UI"
FADE_MS = 200
BAR_ANIM_MS = 250
LOGO_BOX = (480, 330)                   # größtmögliche Anzeigegröße des Logos (geräteunabhängige Pixel); es wird nie beschnitten


def resource_path(name: str) -> str:
    """Mitgelieferte Datei: neben dem Paket, in einer PyInstaller-.exe im entpackten Ordner (sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


class CaptionButton(QToolButton):
    """Minimieren / Schließen; 'danger' = beim Hover rot mit weißer Schrift."""

    def __init__(self, text: str, danger: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setText(text)
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedSize(46, 32)
        hover_bg, hover_fg = (CLOSE_RED, "#FFFFFF") if danger else ("rgba(0,0,0,0.08)", INK)
        self.setStyleSheet("QToolButton{border:none;background:transparent;color:%s;font-family:'Segoe UI Symbol','%s';font-size:13px;}"
                           "QToolButton:hover{background:%s;color:%s;}" % (INK, FONT, hover_bg, hover_fg))


class Splash(QWidget):
    """Ladefenster. set_progress(wert, text): wert 0-100 = bestimmt (weich animiert), wert < 0 = Dauer unbekannt (endlose Animation)."""

    closed_by_user = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFixedSize(WIN_W + 2 * SHADOW, WIN_H + 2 * SHADOW)
        self.setWindowOpacity(0.0)
        self._drag: Optional[QPoint] = None
        self._logo_src: Optional[QPixmap] = None
        self._screen_hooked = False
        self._status_full = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(SHADOW, SHADOW, SHADOW, SHADOW)
        self.card = QFrame(self)
        self.card.setObjectName("card")
        self.card.setStyleSheet("#card{background:%s;border-radius:%dpx;}" % (BG, RADIUS))
        shadow = QGraphicsDropShadowEffect(self.card)
        shadow.setBlurRadius(SHADOW * 1.4)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 95))
        self.card.setGraphicsEffect(shadow)
        outer.addWidget(self.card)

        root = QVBoxLayout(self.card)
        root.setContentsMargins(0, 0, 0, 12)
        root.setSpacing(0)

        top = QHBoxLayout()
        top.setContentsMargins(14, 8, 0, 0)
        top.setSpacing(0)
        chip = QLabel(APP_NAME)
        chip.setStyleSheet("background:%s;color:#FFFFFF;border-radius:4px;padding:3px 10px;font-family:'%s';font-size:12px;font-weight:600;" % (ACCENT, FONT))
        top.addWidget(chip, 0, Qt.AlignLeft | Qt.AlignVCenter)
        top.addStretch(1)
        btn_min = CaptionButton("–")
        btn_min.setToolTip("Minimieren")
        btn_min.clicked.connect(self.showMinimized)
        btn_close = CaptionButton("✕", danger=True)
        btn_close.setToolTip("Schließen")
        btn_close.clicked.connect(self.closed_by_user.emit)
        top.addWidget(btn_min)
        top.addWidget(btn_close)
        root.addLayout(top)

        root.addStretch(1)
        self.logo = QLabel()
        self.logo.setAlignment(Qt.AlignCenter)
        self.logo.setStyleSheet("background:transparent;")
        root.addWidget(self.logo, 0, Qt.AlignHCenter)
        root.addStretch(1)

        self.bar = QProgressBar()
        self.bar.setRange(0, 0)                                          # bis zur ersten Meldung: Dauer unbekannt
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.setStyleSheet("QProgressBar{border:none;border-radius:3px;background:%s;}"
                               "QProgressBar::chunk{border-radius:3px;background:%s;}" % (GROOVE, ACCENT))
        bar_row = QHBoxLayout()
        bar_row.setContentsMargins(16, 0, 16, 0)
        bar_row.addWidget(self.bar)
        root.addLayout(bar_row)
        root.addSpacing(8)

        info = QHBoxLayout()
        info.setContentsMargins(16, 0, 16, 0)
        gray = "color:%s;background:transparent;font-family:'%s';font-size:12px;" % (GRAY, FONT)
        self.status = QLabel("")
        self.status.setStyleSheet(gray)
        self.pct = QLabel("")
        self.pct.setStyleSheet(gray)
        self.pct.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        info.addWidget(self.status, 1)
        info.addWidget(self.pct, 0)
        root.addLayout(info)

        self._bar_anim = QPropertyAnimation(self.bar, b"value", self)
        self._bar_anim.setDuration(BAR_ANIM_MS)
        self._bar_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(FADE_MS)

        self._load_logo()
        self.center()

    # ---------- Logo: vollständig, scharf auch bei hoher Bildschirmskalierung, darf fehlen
    def _load_logo(self) -> None:
        pm = QPixmap(resource_path(LOGO_FILE))
        if pm.isNull():
            self.logo.hide()
            return
        self._logo_src = pm
        self.setWindowIcon(QIcon(pm))
        self._scale_logo()

    @Slot()
    def _scale_logo(self, *_args: Any) -> None:
        if self._logo_src is None:
            return
        dpr = self.devicePixelRatioF()
        scaled = self._logo_src.scaled(int(LOGO_BOX[0] * dpr), int(LOGO_BOX[1] * dpr), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        scaled.setDevicePixelRatio(dpr)
        self.logo.setPixmap(scaled)
        self.logo.setFixedSize(int(scaled.width() / dpr) + 1, int(scaled.height() / dpr) + 1)
        self.logo.show()

    def showEvent(self, e: Any) -> None:                                 # noqa: N802
        super().showEvent(e)
        wh = self.windowHandle()
        if wh is not None and not self._screen_hooked:
            wh.screenChanged.connect(self._scale_logo)
            self._screen_hooked = True
        self._scale_logo()

    def center(self) -> None:
        scr = QApplication.primaryScreen()
        if scr is not None:
            g = scr.availableGeometry()
            self.move(g.center().x() - self.width() // 2, g.center().y() - self.height() // 2)

    # ---------- Status und Fortschritt
    def set_status(self, text: str) -> None:
        self._status_full = text
        self._elide()

    def _elide(self) -> None:
        w = max(100, self.status.width())
        self.status.setText(QFontMetrics(self.status.font()).elidedText(self._status_full, Qt.ElideRight, w))

    def resizeEvent(self, e: Any) -> None:                               # noqa: N802
        super().resizeEvent(e)
        self._elide()

    @Slot(int, str)
    def set_progress(self, value: int, text: str = "") -> None:
        if text:
            self.set_status(text)
        if value < 0:
            self._bar_anim.stop()
            self.bar.setRange(0, 0)
            self.pct.setText("")
            return
        if self.bar.maximum() == 0:
            self.bar.setRange(0, 100)
            self.bar.setValue(0)
        value = max(0, min(100, int(value)))
        self._bar_anim.stop()
        self._bar_anim.setStartValue(self.bar.value())
        self._bar_anim.setEndValue(value)
        self._bar_anim.start()
        self.pct.setText("%d %%" % value)

    # ---------- Ein-/Ausblenden
    def fade_in(self) -> None:
        self.show()
        self._fade.stop()
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()

    def fade_out(self, then: Optional[Callable[[], None]] = None) -> None:
        self._fade.stop()
        self._fade.setStartValue(self.windowOpacity())
        self._fade.setEndValue(0.0)

        def done() -> None:
            self._fade.finished.disconnect(done)
            if then:
                then()
            self.close()
        self._fade.finished.connect(done)
        self._fade.start()

    # ---------- Verschieben mit der Maus
    def mousePressEvent(self, e: Any) -> None:                           # noqa: N802
        if e.button() == Qt.LeftButton:
            wh = self.windowHandle()
            if wh is not None and wh.startSystemMove():
                return
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e: Any) -> None:                            # noqa: N802
        if self._drag is not None and e.buttons() & Qt.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, e: Any) -> None:                         # noqa: N802
        self._drag = None


class _Bridge(QObject):
    """Bringt Meldungen aus dem Arbeits-Thread des Launchers sicher in den Qt-Haupt-Thread (Signale werden dorthin zugestellt)."""
    update = Signal(int, str)
    error = Signal(str, str, str, str)
    close = Signal()


class QtUi:
    """Gleiche Schnittstelle wie die tkinter-Oberfläche des Launchers."""

    def __init__(self) -> None:
        self.app = QApplication.instance() or QApplication(sys.argv[:1])
        self.splash = Splash()
        self.bridge = _Bridge()
        self.bridge.update.connect(self._on_update)
        self.bridge.error.connect(self._on_error)
        self.bridge.close.connect(self._on_close)
        self.splash.closed_by_user.connect(self.app.quit)
        self.failed = False

    # --- Aufrufe aus dem Arbeits-Thread
    def update(self, pct: int, title: str, detail: str) -> None:
        self.bridge.update.emit(int(pct), (title + (" - " + detail if detail else "")) if title else "")

    def log(self, line: str) -> None:
        pass                                                    # das Protokoll steht in launcher.log; der Startbildschirm zeigt nur den Stand

    def error(self, title: str, text: str, details: str, path: str) -> None:
        self.bridge.error.emit(title, text, details, path)

    def finished(self) -> None:
        self.bridge.close.emit()

    # --- im Haupt-Thread
    @Slot(int, str)
    def _on_update(self, pct: int, text: str) -> None:
        self.splash.set_progress(pct, text)

    @Slot(str, str, str, str)
    def _on_error(self, title: str, text: str, details: str, path: str) -> None:
        self.failed = True
        self.splash.setWindowFlag(Qt.WindowStaysOnTopHint, False)
        self.splash.hide()
        box = QMessageBox(QMessageBox.Critical, APP_NAME, "%s\n\n%s\n\nProtokoll: %s" % (title, text, path))
        if details:
            box.setDetailedText(details)
        box.exec()
        self.app.quit()

    @Slot()
    def _on_close(self) -> None:
        self.splash.fade_out(self.app.quit)

    def mainloop(self, launcher: Any) -> None:
        self.splash.fade_in()
        self.app.exec()
