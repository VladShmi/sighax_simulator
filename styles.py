"""
styles.py
Configuracion de colores e interfaz
"""

# ── Paleta de colores ────────────────────────────────────────
C = {
    'bg':          '#0D1117',
    'bg2':         '#161B22',
    'bg3':         '#21262D',
    'bg4':         '#30363D',
    'border':      '#30363D',
    'text':        '#C9D1D9',
    'text_dim':    '#8B949E',
    'text_bright': '#F0F6FC',
    'green':       '#3FB950',
    'green_dark':  '#1A4D24',
    'green_glow':  '#56D364',
    'red':         '#F85149',
    'red_dark':    '#4D1616',
    'orange':      '#E3B341',
    'orange_dark': '#3D2800',
    'blue':        '#58A6FF',
    'blue_dark':   '#0D2845',
    'purple':      '#BC8CFF',
    'purple_dark': '#2D1B4D',
    'cyan':        '#39D0D8',
    'yellow':      '#FFD60A',
}

MAIN_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {C['bg']};
    color: {C['text']};
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}

QTabWidget::pane {{
    border: 1px solid {C['border']};
    background-color: {C['bg2']};
    border-radius: 4px;
}}

QTabBar::tab {{
    background-color: {C['bg3']};
    color: {C['text_dim']};
    padding: 10px 24px;
    border: 1px solid {C['border']};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    font-size: 13px;
    font-weight: bold;
}}

QTabBar::tab:selected {{
    background-color: {C['bg2']};
    color: {C['text_bright']};
    border-bottom-color: {C['bg2']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {C['bg4']};
    color: {C['text']};
}}

QPushButton {{
    background-color: {C['bg3']};
    color: {C['text']};
    border: 1px solid {C['border']};
    padding: 8px 20px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: bold;
}}

QPushButton:hover {{
    background-color: {C['bg4']};
    border-color: {C['blue']};
    color: {C['text_bright']};
}}

QPushButton:pressed {{
    background-color: {C['blue_dark']};
    border-color: {C['blue']};
}}

QPushButton:disabled {{
    color: {C['text_dim']};
    border-color: {C['border']};
}}

QPushButton#btn_run_verify {{
    background-color: {C['green_dark']};
    border-color: {C['green']};
    color: {C['green_glow']};
}}
QPushButton#btn_run_verify:hover {{
    background-color: #224D2A;
    border-color: {C['green_glow']};
}}

QPushButton#btn_run_exploit {{
    background-color: {C['red_dark']};
    border-color: {C['red']};
    color: {C['red']};
}}
QPushButton#btn_run_exploit:hover {{
    background-color: #661A18;
    border-color: #FF6B67;
    color: #FF6B67;
}}

QPushButton#btn_reset {{
    background-color: {C['bg3']};
    border-color: {C['orange']};
    color: {C['orange']};
}}

QTextEdit, QPlainTextEdit {{
    background-color: {C['bg']};
    color: {C['text']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 11px;
    padding: 4px;
    selection-background-color: {C['blue_dark']};
}}

QLabel {{
    color: {C['text']};
}}

QLabel#label_title {{
    font-size: 22px;
    font-weight: bold;
    color: {C['text_bright']};
}}

QLabel#label_subtitle {{
    font-size: 12px;
    color: {C['text_dim']};
}}

QScrollBar:vertical {{
    background: {C['bg2']};
    width: 8px;
    border: none;
}}

QScrollBar::handle:vertical {{
    background: {C['bg4']};
    border-radius: 4px;
    min-height: 20px;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QSplitter::handle {{
    background-color: {C['border']};
    width: 2px;
}}

QGroupBox {{
    border: 1px solid {C['border']};
    border-radius: 6px;
    margin-top: 12px;
    padding: 8px;
    color: {C['text_dim']};
    font-size: 11px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {C['blue']};
    font-weight: bold;
    font-size: 11px;
}}

QProgressBar {{
    border: 1px solid {C['border']};
    border-radius: 4px;
    background-color: {C['bg']};
    height: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {C['green']};
    border-radius: 4px;
}}
"""

# ── Colores por tipo de paso ─────────────────────────────────
STEP_COLORS = {
    'INFO':   {'bg': C['bg3'],        'border': C['border'],  'text': C['text'],        'tag_bg': C['bg4'],       'tag_fg': C['text_dim']},
    'PASS':   {'bg': C['green_dark'], 'border': C['green'],   'text': C['text_bright'], 'tag_bg': C['green'],     'tag_fg': '#000'},
    'FAIL':   {'bg': C['red_dark'],   'border': C['red'],     'text': '#FFB3B0',        'tag_bg': C['red'],       'tag_fg': '#000'},
    'VULN':   {'bg': C['orange_dark'],'border': C['orange'],  'text': C['orange'],      'tag_bg': C['orange'],    'tag_fg': '#000'},
    'EXPLOIT':{'bg': '#2D1A00',       'border': C['orange'],  'text': '#FFD080',        'tag_bg': '#E37400',      'tag_fg': '#000'},
    'BYPASS': {'bg': C['purple_dark'],'border': C['purple'],  'text': C['purple'],      'tag_bg': C['purple'],    'tag_fg': '#000'},
    'PWNED':  {'bg': '#2D0D0D',       'border': '#FF3B3B',    'text': '#FF6B6B',        'tag_bg': '#FF3B3B',      'tag_fg': '#000'},
    'VERIFIED ✓': {'bg': '#0D2D0D',  'border': C['green'],   'text': C['green_glow'],  'tag_bg': C['green'],     'tag_fg': '#000'},
}

# ── HTML para el header de la app ───────────────────────────
HEADER_HTML = f"""
<div style="
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['bg']}, stop:0.5 {C['bg2']}, stop:1 {C['bg']});
    border-bottom: 1px solid {C['border']};
    padding: 12px 20px;
">
  <span style="color:{C['red']};font-size:20px;font-weight:bold;">SIGHAX</span>
  <span style="color:{C['text_dim']};font-size:14px;"> / ARM9 Bootrom Exploit Simulator</span>
  <span style="color:{C['text_dim']};font-size:11px;float:right;">3DS · SciresM 2017 · Demo educativo</span>
</div>
"""

def step_card_style(tag: str) -> str:
    sc  = STEP_COLORS.get(tag, STEP_COLORS['INFO'])
    return (
        f"background-color:{sc['bg']};"
        f"border:1px solid {sc['border']};"
        f"border-radius:8px;"
        f"margin:4px 0;"
        f"padding:10px;"
    )

def tag_style(tag: str) -> str:
    sc = STEP_COLORS.get(tag, STEP_COLORS['INFO'])
    return (
        f"background-color:{sc['tag_bg']};"
        f"color:{sc['tag_fg']};"
        f"border-radius:4px;"
        f"padding:2px 8px;"
        f"font-weight:bold;"
        f"font-size:10px;"
    )