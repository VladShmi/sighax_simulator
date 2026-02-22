"""
ui_anatomy.py — Widget de Anatomía del Bloque de Firma
Visualizador animado del bloque RSA/PKCS#1 v1.5.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTextEdit, QSizePolicy, QScrollArea
)
from PyQt6.QtCore  import Qt, QRect, QPoint, pyqtSignal, QTimer, QPropertyAnimation
from PyQt6.QtGui   import QPainter, QColor, QFont, QFontMetrics, QPen, QBrush, QPainterPath

from styles import C


# ─── Definición de regiones del bloque ───────────────────────

REGIONS = [
    {
        'id':    'byte0',
        'label': '00',
        'name':  'Inicio de firma',
        'desc':  'Siempre 0x00. Declara el inicio de un bloque de firma RSA.\nSi no es 0x00 → FIRM rechazado inmediatamente.',
        'color': '#39D0D8',
        'size':  1,
    },
    {
        'id':    'padtype',
        'label': '01 / 02',
        'name':  'Tipo de padding',
        'desc':  '0x01 = CON padding 0xFF (seguro)\n0x02 = SIN padding (inseguro)\n\nEl bootROM acepta ambos valores.\nAceptar 0x02 es la VULNERABILIDAD 1:\nsin padding el espacio de brute-force se reduce drásticamente.',
        'color': '#BC8CFF',
        'size':  1,
    },
    {
        'id':    'padding',
        'label': 'FF FF ... FF',
        'name':  'Padding 0xFF',
        'desc':  'Relleno de bytes 0xFF hasta el separador.\nSolo presente si padding type = 0x01.\nEl bootROM verifica que todos sean 0xFF.\n\nCon padding type 0x02 esta región no existe.',
        'color': '#30363D',
        'size':  8,   # visual weight
    },
    {
        'id':    'separator',
        'label': '00',
        'name':  'Separador',
        'desc':  'Byte 0x00 que marca el fin del padding.\nEl parser avanza hasta encontrar este byte.',
        'color': '#39D0D8',
        'size':  1,
    },
    {
        'id':    'asn1',
        'label': '30  31  30',
        'name':  'ASN.1',
        'desc':  '0x30 → verificado por el bootROM (debe ser 0x30)\n0x31 → IGNORADO completamente por el bootROM\n0x30 → verificado por el bootROM (debe ser 0x30)\n\nEl 0x31 ignorado es otra descuido de Nintendo.',
        'color': '#58A6FF',
        'size':  3,
    },
    {
        'id':    'len_byte',
        'label': '0D',
        'name':  '⚡ Byte de longitud',
        'desc':  'VULNERABILIDAD 2 — El corazón del exploit.\n\nEste byte indica al parser cuántos bytes saltar a continuación.\nValor legítimo: 0x0D (= 13 bytes).\n\nSi el atacante lo cambia, puede mover el puntero del parser\na cualquier posición del bloque → truco sighax.',
        'color': '#FFD60A',
        'size':  1,
    },
    {
        'id':    'inner',
        'label': 'OID SHA-256  (13 bytes)',
        'name':  'Inner block (OID)',
        'desc':  'Identificador del algoritmo de hash usado (OID SHA-256).\n13 bytes: 06 09 60 86 48 01 65 03 04 02 01 05 00\n\nEl parser salta este bloque COMPLETAMENTE sin leerlo.\nSu longitud viene dictada por el byte anterior (0x0D).',
        'color': '#3D2800',
        'size':  5,
    },
    {
        'id':    'ignored',
        'label': '04  20',
        'name':  'Ignorados',
        'desc':  'Bytes 0x04 y 0x20.\nIgnorados por el bootROM. El parser los salta.\nOtro ejemplo de verificación incompleta.',
        'color': '#21262D',
        'size':  2,
    },
    {
        'id':    'correct_hash',
        'label': 'correct_hash  (32 bytes SHA-256)',
        'name':  'correct_hash',
        'desc':  'Los 32 bytes del hash SHA-256 correcto del FIRM,\ncifrado dentro del bloque de firma.\n\nEl parser lee estos 32 bytes y luego salta otros 32\npara ir al calculated_hash.\n\nEN EL EXPLOIT: el puntero aterriza AQUÍ en vez de en\nla posición anterior → el parser cree estar en correct_hash\npero está en calculated_hash.',
        'color': '#1A4D24',
        'size':  8,
    },
    {
        'id':    'calc_hash',
        'label': 'calculated_hash  (32 bytes — generado en runtime)',
        'name':  'calculated_hash',
        'desc':  'Zona de memoria FUERA del bloque de firma.\n\nEl bootROM genera SHA-256 del FIRM en tiempo real y lo escribe aquí.\nLuego compara este valor con correct_hash.\n\nEN EL EXPLOIT: el puntero acaba aquí, FUERA del bloque.\nEl bootROM escribe calculated_hash aún más afuera y compara\ncalculated_hash vs sí mismo → siempre coincide.',
        'color': '#0D2845',
        'size':  8,
    },
]


# ─── Widget de bloque visual ──────────────────────────────────

class BlockBar(QWidget):
    """
    Barra horizontal que muestra las regiones del bloque de firma.
    Permite hacer clic en cada región para ver su descripción.
    Muestra un puntero animado en la posición actual del parser.
    """
    region_clicked = pyqtSignal(str)  # Emite el id de la región

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(80)
        self.setMaximumHeight(80)
        self._active_region  = None
        self._pointer_region = None
        self._rects          = []  # (QRect, region_dict) calculados en paintEvent
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_active(self, region_id: str | None):
        """Resalta una región (paso del parser)."""
        self._active_region = region_id
        self.update()

    def set_pointer(self, region_id: str | None):
        """Mueve el puntero del parser a una región."""
        self._pointer_region = region_id
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w     = self.width()
        h     = self.height()
        bar_h = 44
        bar_y = 20
        total = sum(r['size'] for r in REGIONS)
        x     = 0
        self._rects = []

        for reg in REGIONS:
            rw = int(w * reg['size'] / total)
            rect = QRect(x, bar_y, rw - 1, bar_h)
            self._rects.append((rect, reg))

            # Fondo
            is_active  = (reg['id'] == self._active_region)
            is_pointer = (reg['id'] == self._pointer_region)
            color      = QColor(reg['color'])
            if is_active:
                color = color.lighter(200)
            elif is_pointer:
                color = color.lighter(150)

            painter.fillRect(rect, color)

            # Borde
            pen_color = QColor('#FFD60A') if is_active else (
                        QColor('#58A6FF') if is_pointer else QColor(C['border']))
            painter.setPen(QPen(pen_color, 2 if (is_active or is_pointer) else 1))
            painter.drawRect(rect)

            # Texto dentro de la celda
            painter.setPen(QPen(QColor('#FFFFFF' if is_active else C['text_dim'])))
            font = QFont('Consolas', 8 if rw > 60 else 7)
            font.setBold(is_active)
            painter.setFont(font)
            label = reg['label'] if rw > 30 else reg['label'][:4]
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, label)

            # Puntero (triángulo)
            if is_pointer:
                ptr_x = rect.center().x()
                ptr_y = bar_y - 2
                path = QPainterPath()
                path.moveTo(ptr_x, ptr_y)
                path.lineTo(ptr_x - 7, ptr_y - 12)
                path.lineTo(ptr_x + 7, ptr_y - 12)
                path.closeSubpath()
                painter.fillPath(path, QColor('#58A6FF'))

            x += rw

        # Etiquetas debajo
        x = 0
        for rect, reg in self._rects:
            painter.setPen(QPen(QColor(
                '#FFD60A' if reg['id'] == self._active_region
                else C['text_dim']
            )))
            font = QFont('Consolas', 7)
            painter.setFont(font)
            label_rect = QRect(rect.x(), bar_y + bar_h + 2, rect.width(), 14)
            short = reg['name'][:12] if rect.width() < 80 else reg['name'][:20]
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, short)

    def mousePressEvent(self, event):
        pos = event.pos()
        for rect, reg in self._rects:
            if rect.contains(pos):
                self.region_clicked.emit(reg['id'])
                self.set_active(reg['id'])
                break


# ─── Widget completo de anatomía ─────────────────────────────

class SignatureAnatomy(QWidget):
    """
    Panel completo: barra visual + descripción de la región seleccionada.
    Se integra en la parte superior de cada tab.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("anatomy_panel")
        self.setStyleSheet(
            f"QWidget#anatomy_panel {{"
            f"  background:{C['bg2']};"
            f"  border:1px solid {C['border']};"
            f"  border-radius:8px;"
            f"}}"
            f"QLabel {{ background:transparent;border:none; }}"
        )
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        # Título
        title_row = QHBoxLayout()
        title = QLabel("Anatomía del bloque de firma  —  haz clic en cualquier región para ver su descripción")
        title.setStyleSheet(f"color:{C['text_dim']};font-size:11px;")
        title_row.addWidget(title)

        self._vuln_badge = QLabel("  ⚡ = vulnerabilidad  ")
        self._vuln_badge.setStyleSheet(
            f"color:#000;background:#FFD60A;border-radius:4px;font-size:10px;font-weight:bold;padding:2px 6px;"
        )
        title_row.addWidget(self._vuln_badge)
        title_row.addStretch()
        layout.addLayout(title_row)

        # Barra visual
        self._bar = BlockBar()
        self._bar.region_clicked.connect(self._on_region_clicked)
        layout.addWidget(self._bar)

        # Panel de descripción
        self._desc_frame = QFrame()
        self._desc_frame.setStyleSheet(
            f"QFrame {{background:{C['bg3']};border:1px solid {C['border']};border-radius:6px;}}"
            f"QLabel {{background:transparent;border:none;}}"
        )
        desc_layout = QHBoxLayout(self._desc_frame)
        desc_layout.setContentsMargins(12, 8, 12, 8)
        desc_layout.setSpacing(12)

        self._region_name = QLabel("← Haz clic en una región")
        self._region_name.setStyleSheet(
            f"color:{C['text_bright']};font-size:13px;font-weight:bold;min-width:180px;"
        )
        desc_layout.addWidget(self._region_name)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet(f"color:{C['border']};")
        desc_layout.addWidget(sep)

        self._region_desc = QLabel("Selecciona una región del bloque de firma para ver su descripción detallada.")
        self._region_desc.setWordWrap(True)
        self._region_desc.setStyleSheet(
            f"color:{C['text_dim']};font-size:11px;font-family:'Consolas','Fira Code',monospace;"
        )
        desc_layout.addWidget(self._region_desc, 1)

        layout.addWidget(self._desc_frame)

        # Mapa de regiones para lookup
        self._region_map = {r['id']: r for r in REGIONS}

    def _on_region_clicked(self, region_id: str):
        reg = self._region_map.get(region_id)
        if not reg:
            return
        self._region_name.setText(reg['name'])
        self._region_name.setStyleSheet(
            f"color:{reg['color'] if reg['id'] != 'len_byte' else '#FFD60A'};"
            f"font-size:13px;font-weight:bold;min-width:180px;"
        )
        self._region_desc.setText(reg['desc'])

    def highlight(self, region_id: str | None):
        """Resalta una región desde el exterior (por los pasos)."""
        self._bar.set_active(region_id)
        if region_id:
            self._on_region_clicked(region_id)

    def set_pointer(self, region_id: str | None):
        self._bar.set_pointer(region_id)

    def highlight_and_point(self, region_id: str | None):
        self.highlight(region_id)
        self.set_pointer(region_id)