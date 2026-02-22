"""
ui_verify.py — 
Verificación de legitimidad
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from styles import C, STEP_COLORS, tag_style
from ui_block_visualizer import BlockVisualizer

# Mapa de highlight_bytes → id de segmento en el visualizador
HIGHLIGHT_TO_SEG = {
    'header':        'start',
    'padtype':       'padtype',
    'padding':       'padding',
    'separator':     'sep',
    'der':           'asn1_30a',
    'ignored':       'asn1_31',
    'key_byte':      'len_byte',
    'inner':         'inner',
    'skipped':       'inner',
    'hash':          'correct_hash',
    'hash_confused': 'correct_hash',
    'vuln':          'padtype',
}


def get_cursor_and_active(step: dict):
    """Extrae el segmento donde está el cursor y el activo para este paso."""
    highlights = step.get('highlight_bytes', {})
    if not highlights:
        return None, None
    types = list(highlights.values())
    seg = HIGHLIGHT_TO_SEG.get(types[0])
    return seg, seg


class VerifyWidget(QWidget):
    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine      = engine
        self._anim_speed = 1400
        self._steps      = []
        self._step_idx   = 0
        self._timer      = QTimer()
        self._timer.timeout.connect(self._next_step)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        # ── Contexto ─────────────────────────────────────────
        ctx = QLabel(
            "Cada vez que enciendes la 3DS, el bootROM ARM9 descifra la firma del FIRM con la clave pública\n"
            "de Nintendo y verifica el bloque resultante byte a byte. Aquí puedes ver ese proceso en tiempo real."
        )
        ctx.setWordWrap(True)
        ctx.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;"
            f"background:{C['bg3']};border:1px solid {C['border']};"
            f"border-radius:6px;padding:10px;"
        )
        root.addWidget(ctx)

        # ── Visualizador ──────────────────────────────────────
        self._viz = BlockVisualizer()
        root.addWidget(self._viz)

        # ── Zona de resultado ─────────────────────────────────
        result_row = QHBoxLayout()

        # Firma legítima visual
        firm_box = QFrame()
        firm_box.setStyleSheet(
            f"QFrame {{background:{C['bg3']};border:1px solid {C['border']};border-radius:6px;}}"
            f"QLabel {{background:transparent;border:none;}}"
        )
        firm_l = QVBoxLayout(firm_box)
        firm_l.setContentsMargins(12, 8, 12, 8)
        firm_l.setSpacing(4)
        QLabel("FIRM verificado", parent=firm_box).setStyleSheet(
            f"color:{C['text_dim']};font-size:10px;"
        )
        firm_title = QLabel("NATIVE_FIRM  ·  Nintendo")
        firm_title.setStyleSheet(f"color:{C['text_bright']};font-size:12px;font-weight:bold;")
        lbl_fw = QLabel("FIRM verificado")
        lbl_fw.setStyleSheet(f"color:{C['text_dim']};font-size:10px;")
        firm_l.addWidget(lbl_fw)
        firm_l.addWidget(firm_title)
        ok_lbl = QLabel("Firmado por Nintendo  ·  Firma RSA-2048 válida  ·  SHA-256 verificado")
        ok_lbl.setStyleSheet(f"color:{C['green']};font-size:11px;")
        firm_l.addWidget(ok_lbl)
        result_row.addWidget(firm_box, 1)

        root.addLayout(result_row)

        # ── Controles ─────────────────────────────────────────
        ctrl = QHBoxLayout()

        self._btn_run = QPushButton("▶  Ejecutar verificación")
        self._btn_run.setObjectName("btn_run_verify")
        self._btn_run.setFixedHeight(40)
        self._btn_run.clicked.connect(self._do_run)
        ctrl.addWidget(self._btn_run)

        self._btn_step = QPushButton("⏭  Paso a paso")
        self._btn_step.setFixedHeight(40)
        self._btn_step.clicked.connect(self._do_step)
        ctrl.addWidget(self._btn_step)

        self._btn_reset = QPushButton("↺  Reset")
        self._btn_reset.setObjectName("btn_reset")
        self._btn_reset.setFixedHeight(40)
        self._btn_reset.clicked.connect(self._do_reset)
        ctrl.addWidget(self._btn_reset)

        root.addLayout(ctrl)

        # ── Barra de estado ───────────────────────────────────
        self._status = QLabel("Pulsa ▶ para ver cómo el bootROM verifica el FIRM byte a byte.")
        self._status.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;"
            f"background:{C['bg3']};border-top:1px solid {C['border']};padding:6px 12px;"
        )
        root.addWidget(self._status)

    def _load_steps(self):
        fw = b'NATIVE_FIRM v11.17 ARM9=0x08006000 ARM11=0x1FF80000'
        self._steps  = self.engine.bootrom_verify_correct(fw)
        self._step_idx = 0

    def _do_run(self):
        self._load_steps()
        self._btn_run.setEnabled(False)
        self._btn_step.setEnabled(False)
        self._timer.start(self._anim_speed)

    def _do_step(self):
        if not self._steps:
            self._load_steps()
        self._timer.stop()
        self._show_step(self._step_idx)
        self._step_idx += 1
        if self._step_idx >= len(self._steps):
            self._btn_run.setEnabled(True)
            self._btn_step.setEnabled(True)
            self._step_idx = 0

    def _next_step(self):
        if self._step_idx >= len(self._steps):
            self._timer.stop()
            self._btn_run.setEnabled(True)
            self._btn_step.setEnabled(True)
            return
        self._show_step(self._step_idx)
        self._step_idx += 1

    def _show_step(self, idx: int):
        if idx >= len(self._steps):
            return
        s   = self._steps[idx]
        tag = s.get('tag', 'INFO')
        cursor_seg, active_seg = get_cursor_and_active(s)

        # Construir descripción concisa
        vals_text = ''
        if 'vals' in s:
            vals_text = '\n'.join(f"  {k}: {v}" for k, v in list(s['vals'].items())[:4])

        self._viz.set_parser_state(
            step_num    = s['id'],
            title       = s['title'],
            description = vals_text,
            cursor_seg  = cursor_seg,
            active_seg  = active_seg,
            tag         = tag,
        )

        # Actualizar estado
        TAG_COLORS = {
            'INFO': C['text_dim'], 'PASS': C['green'],
            'FAIL': C['red'], 'VERIFIED ✓': C['green'],
        }
        clr = TAG_COLORS.get(tag, C['text_dim'])
        self._status.setStyleSheet(
            f"color:{clr};font-size:11px;"
            f"background:{C['bg3']};border-top:1px solid {C['border']};padding:6px 12px;"
        )
        msg = f"[{tag}]  {s['title']}"
        if s.get('fatal'):
            msg = f"✗ DETENIDO — {s['title']}"
        self._status.setText(msg)

    def _do_reset(self):
        self._timer.stop()
        self._steps    = []
        self._step_idx = 0
        self._viz.reset()
        self._btn_run.setEnabled(True)
        self._btn_step.setEnabled(True)
        self._status.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;"
            f"background:{C['bg3']};border-top:1px solid {C['border']};padding:6px 12px;"
        )
        self._status.setText("Pulsa ▶ para ver cómo el bootROM verifica el FIRM byte a byte.")