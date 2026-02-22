"""
ui_block_visualizer.py
Visualizador animado de firma RSA.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy
from PyQt6.QtCore    import Qt, QTimer, QRect, QPropertyAnimation, QEasingCurve, pyqtSignal
from PyQt6.QtGui     import QPainter, QColor, QFont, QPen, QBrush, QPainterPath, QLinearGradient

from styles import C

# ─── Definición de segmentos del bloque ──────────────────────

SEGMENTS = [
    {
        'id':      'start',
        'bytes':   '00',
        'label':   'INICIO',
        'detail':  'Siempre 0x00\nInicio de bloque',
        'color':   '#39D0D8',
        'weight':  1.2,
        'vuln':    False,
    },
    {
        'id':      'padtype',
        'bytes':   '01',
        'label':   'PAD TYPE',
        'detail':  '0x01 = con padding\n0x02 = sin padding\n⚠ bootROM acepta ambos',
        'color':   '#BC8CFF',
        'weight':  1.4,
        'vuln':    True,
        'vuln_label': 'VULN 1',
    },
    {
        'id':      'padding',
        'bytes':   'FF FF FF ... FF',
        'label':   'PADDING',
        'detail':  'Bytes 0xFF\nRelleno de seguridad\n(ausente si pad type=0x02)',
        'color':   '#3D444D',
        'weight':  5.0,
        'vuln':    False,
    },
    {
        'id':      'sep',
        'bytes':   '00',
        'label':   'SEP',
        'detail':  'Separador 0x00\nFin del padding',
        'color':   '#39D0D8',
        'weight':  1.0,
        'vuln':    False,
    },
    {
        'id':      'asn1_30a',
        'bytes':   '30',
        'label':   '30',
        'detail':  'ASN.1 — verificado',
        'color':   '#2D4A6B',
        'weight':  0.9,
        'vuln':    False,
    },
    {
        'id':      'asn1_31',
        'bytes':   '31',
        'label':   '31 ✗',
        'detail':  '¡IGNORADO por bootROM!\nNintendo se olvidó de verificarlo',
        'color':   '#1A1A2E',
        'weight':  0.9,
        'vuln':    False,
    },
    {
        'id':      'asn1_30b',
        'bytes':   '30',
        'label':   '30',
        'detail':  'ASN.1 — verificado',
        'color':   '#2D4A6B',
        'weight':  0.9,
        'vuln':    False,
    },
    {
        'id':      'len_byte',
        'bytes':   '0D',
        'label':   '⚡ 0x0D',
        'detail':  'LONGITUD del inner block\nDice al parser cuántos bytes saltar\n¡ESTA ES LA CLAVE DEL EXPLOIT!',
        'color':   '#5A4000',
        'weight':  1.5,
        'vuln':    True,
        'vuln_label': 'VULN 2',
    },
    {
        'id':      'inner',
        'bytes':   '06 09 60 ... 00',
        'label':   'OID SHA-256',
        'detail':  'Identificador del algoritmo\n(13 bytes)\nEl parser lo SALTA sin leer',
        'color':   '#1E1E2E',
        'weight':  4.0,
        'vuln':    False,
    },
    {
        'id':      'ignored2',
        'bytes':   '04 20',
        'label':   '04 20 ✗',
        'detail':  'También IGNORADOS por bootROM',
        'color':   '#1A1A1A',
        'weight':  1.2,
        'vuln':    False,
    },
    {
        'id':      'correct_hash',
        'bytes':   'SHA-256 (32 bytes)',
        'label':   'correct_hash',
        'detail':  'Hash SHA-256 correcto del FIRM\nFirmado por Nintendo\n\nEN EL EXPLOIT:\nel puntero aterriza AQUÍ',
        'color':   '#1A4D24',
        'weight':  5.0,
        'vuln':    False,
    },
    {
        'id':      'calc_hash',
        'bytes':   '← generado en runtime',
        'label':   'calculated_hash',
        'detail':  'Zona FUERA del bloque de firma\nEl bootROM escribe aquí\nel hash calculado en tiempo real\n\nEN EL EXPLOIT: se compara\nconsigo mismo → siempre ✓',
        'color':   '#0D2845',
        'weight':  5.0,
        'vuln':    False,
        'outside': True,
    },
]

SEG_MAP = {s['id']: s for s in SEGMENTS}

# Mapa de tipos de highlight (desde crypto_engine) → id de segmento del visualizador
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


class BlockBar(QWidget):
    """
    Barra visual del bloque de firma con cursor animado.
    """
    clicked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(110)
        self.setMaximumHeight(110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._active_id  = None
        self._cursor_id  = None
        self._exploit_mode = False
        self._rects      = []
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_active(self, seg_id: str | None):
        self._active_id = seg_id
        self.update()

    def set_cursor(self, seg_id: str | None):
        self._cursor_id = seg_id
        self.update()

    def set_exploit_mode(self, val: bool):
        self._exploit_mode = val
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w       = self.width()
        bar_h   = 58
        bar_y   = 30
        total   = sum(s['weight'] for s in SEGMENTS)
        x       = 0
        self._rects = []

        cursor_x = -1

        for seg in SEGMENTS:
            sw   = max(int(w * seg['weight'] / total), 20)
            rect = QRect(x, bar_y, sw - 2, bar_h)
            self._rects.append((rect, seg))

            is_active  = (seg['id'] == self._active_id)
            is_cursor  = (seg['id'] == self._cursor_id)
            is_outside = seg.get('outside', False)

            # Color de fondo
            base_color = QColor(seg['color'])
            if is_active:
                base_color = base_color.lighter(220)
            elif is_cursor:
                base_color = base_color.lighter(170)

            # Fondo con gradiente para segmentos activos
            if is_active or is_cursor:
                grad = QLinearGradient(rect.x(), rect.y(), rect.x(), rect.bottom())
                grad.setColorAt(0, base_color.lighter(130))
                grad.setColorAt(1, base_color)
                painter.fillRect(rect, QBrush(grad))
            else:
                painter.fillRect(rect, base_color)

            # Borde especial para outside
            if is_outside:
                pen = QPen(QColor('#58A6FF'), 2, Qt.PenStyle.DashLine)
            elif is_active:
                pen = QPen(QColor('#FFD60A'), 3)
            elif is_cursor:
                pen = QPen(QColor('#58A6FF'), 2)
            elif seg.get('vuln'):
                pen = QPen(QColor('#FFD60A'), 2)
            else:
                pen = QPen(QColor(C['border']), 1)
            painter.setPen(pen)
            painter.drawRect(rect)

            # Badge de vulnerabilidad
            if seg.get('vuln') and sw > 40:
                badge_rect = QRect(rect.x() + 2, rect.y() + 2, 48, 14)
                painter.fillRect(badge_rect, QColor('#FFD60A'))
                painter.setPen(QPen(QColor('#000')))
                font = QFont('Consolas', 7)
                font.setBold(True)
                painter.setFont(font)
                painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, seg.get('vuln_label','VULN'))

            # Label principal
            color = QColor('#FFFFFF') if is_active else (
                    QColor('#FFD60A') if seg.get('vuln') else QColor(C['text_dim']))
            painter.setPen(QPen(color))
            font = QFont('Consolas', 8 if sw > 80 else 7)
            font.setBold(is_active or is_cursor)
            painter.setFont(font)
            label = seg['label']
            if sw < 35:
                label = label[:4]
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, label)

            # Bytes debajo del label (solo si hay espacio)
            if sw > 70 and not is_active:
                bfont = QFont('Consolas', 7)
                painter.setFont(bfont)
                bcolor = QColor(C['text_dim'])
                bcolor.setAlpha(150)
                painter.setPen(QPen(bcolor))
                byte_rect = QRect(rect.x(), rect.y() + bar_h - 16, sw - 2, 16)
                btext = seg['bytes'][:16] if sw < 120 else seg['bytes']
                painter.drawText(byte_rect, Qt.AlignmentFlag.AlignCenter, btext)

            # Guardar posición del cursor
            if is_cursor:
                cursor_x = rect.center().x()

            x += sw

        # Dibujar cursor (triángulo arriba de la barra)
        if cursor_x >= 0:
            ptr_y = bar_y - 2
            path = QPainterPath()
            path.moveTo(cursor_x, ptr_y)
            path.lineTo(cursor_x - 9, ptr_y - 16)
            path.lineTo(cursor_x + 9, ptr_y - 16)
            path.closeSubpath()
            painter.fillPath(path, QColor('#58A6FF'))
            painter.setPen(QPen(QColor('#39D0D8'), 1))
            painter.drawPath(path)

            # Línea vertical punteada hacia abajo
            pen = QPen(QColor('#58A6FF'), 1, Qt.PenStyle.DotLine)
            painter.setPen(pen)
            painter.drawLine(cursor_x, ptr_y, cursor_x, bar_y + bar_h + 10)

        # Etiquetas debajo
        for rect, seg in self._rects:
            is_active = (seg['id'] == self._active_id)
            painter.setPen(QPen(QColor('#FFD60A' if is_active else C['text_dim'])))
            font = QFont('Consolas', 7)
            font.setBold(is_active)
            painter.setFont(font)
            label_rect = QRect(rect.x(), bar_y + bar_h + 2, rect.width(), 14)
            short = seg['label'][:10] if rect.width() < 90 else seg['label']
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, short)

    def mousePressEvent(self, event):
        for rect, seg in self._rects:
            if rect.contains(event.pos()):
                self.clicked.emit(seg['id'])
                self.set_active(seg['id'])
                break


class BlockVisualizer(QWidget):
    """
    Widget completo: barra + panel de descripción + estado del parser.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Título
        title_row = QHBoxLayout()
        t = QLabel("Bloque de firma RSA descifrado  —  el parser del bootROM lo lee de izquierda a derecha")
        t.setStyleSheet(f"color:{C['text_dim']};font-size:11px;")
        title_row.addWidget(t)

        for txt, clr in [("⚡ = vulnerabilidad", '#FFD60A'), ("· · · = fuera del bloque", C['blue'])]:
            b = QLabel(f"  {txt}  ")
            b.setStyleSheet(
                f"color:{'#000' if clr == '#FFD60A' else clr};"
                f"background:{'#FFD60A' if clr == '#FFD60A' else 'transparent'};"
                f"border:1px solid {clr};border-radius:3px;"
                f"font-size:10px;padding:1px 4px;"
            )
            title_row.addWidget(b)
        title_row.addStretch()
        layout.addLayout(title_row)

        # Barra principal
        self._bar = BlockBar()
        self._bar.clicked.connect(self._on_click)
        layout.addWidget(self._bar)

        # Panel inferior: descripción + estado
        bottom = QHBoxLayout()
        bottom.setSpacing(10)

        # Descripción de la región activa
        self._desc_frame = QFrame()
        self._desc_frame.setMinimumWidth(260)
        self._desc_frame.setMaximumWidth(320)
        self._desc_frame.setStyleSheet(
            f"QFrame {{background:{C['bg3']};border:1px solid {C['border']};border-radius:6px;}}"
            f"QLabel {{background:transparent;border:none;}}"
        )
        desc_l = QVBoxLayout(self._desc_frame)
        desc_l.setContentsMargins(10, 8, 10, 8)

        self._region_title = QLabel("← Haz clic en un segmento")
        self._region_title.setStyleSheet(
            f"color:{C['text_bright']};font-size:12px;font-weight:bold;"
        )
        desc_l.addWidget(self._region_title)

        self._region_desc = QLabel("Selecciona cualquier región\npara ver qué hace el parser\ncuando llega a ese punto.")
        self._region_desc.setWordWrap(True)
        self._region_desc.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;"
            f"font-family:'Consolas','Fira Code',monospace;"
        )
        desc_l.addWidget(self._region_desc)
        bottom.addWidget(self._desc_frame)

        # Estado del parser (texto principal)
        self._parser_frame = QFrame()
        self._parser_frame.setStyleSheet(
            f"QFrame {{background:{C['bg2']};border:1px solid {C['border']};border-radius:6px;}}"
            f"QLabel {{background:transparent;border:none;}}"
        )
        parser_l = QVBoxLayout(self._parser_frame)
        parser_l.setContentsMargins(12, 8, 12, 8)

        self._step_label = QLabel("Paso actual del parser")
        self._step_label.setStyleSheet(
            f"color:{C['text_dim']};font-size:10px;font-weight:bold;"
        )
        parser_l.addWidget(self._step_label)

        self._parser_text = QLabel("Ejecuta la verificación para ver\ncómo el parser recorre el bloque byte a byte.")
        self._parser_text.setWordWrap(True)
        self._parser_text.setStyleSheet(
            f"color:{C['text_bright']};font-size:13px;"
            f"font-family:'Consolas','Fira Code',monospace;"
        )
        parser_l.addWidget(self._parser_text)
        bottom.addWidget(self._parser_frame, 1)

        layout.addLayout(bottom)

    def _on_click(self, seg_id: str):
        seg = SEG_MAP.get(seg_id)
        if not seg:
            return
        color = seg['color']
        self._region_title.setText(seg['label'])
        self._region_title.setStyleSheet(
            f"color:{'#FFD60A' if seg.get('vuln') else C['text_bright']};"
            f"font-size:12px;font-weight:bold;"
        )
        self._region_desc.setText(seg['detail'])

    def set_parser_state(self, step_num: int, title: str, description: str,
                          cursor_seg: str | None, active_seg: str | None,
                          tag: str = 'INFO'):
        TAG_COLORS = {
            'INFO': C['text_dim'],
            'PASS': C['green'],
            'FAIL': C['red'],
            'VULN': C['orange'],
            'EXPLOIT': '#FFD080',
            'BYPASS': C['purple'],
            'PWNED': '#FF3B3B',
            'VERIFIED ✓': C['green'],
        }
        color = TAG_COLORS.get(tag, C['text_dim'])

        self._step_label.setText(f"Paso {step_num:02d}  —  {tag}")
        self._step_label.setStyleSheet(
            f"color:{color};font-size:10px;font-weight:bold;"
        )
        self._parser_text.setText(f"{title}\n\n{description}")
        self._parser_text.setStyleSheet(
            f"color:{C['text_bright']};font-size:12px;"
            f"font-family:'Consolas','Fira Code',monospace;"
        )

        self._bar.set_cursor(cursor_seg)
        self._bar.set_active(active_seg)

        if active_seg:
            self._on_click(active_seg)

    def reset(self):
        self._bar.set_cursor(None)
        self._bar.set_active(None)
        self._region_title.setText("← Haz clic en un segmento")
        self._region_desc.setText(
            "Selecciona cualquier región\npara ver qué hace el parser\ncuando llega a ese punto."
        )
        self._parser_text.setText(
            "Ejecuta la verificación para ver\ncómo el parser recorre el bloque byte a byte."
        )
        self._step_label.setText("Paso actual del parser")
        self._step_label.setStyleSheet(
            f"color:{C['text_dim']};font-size:10px;font-weight:bold;"
        )