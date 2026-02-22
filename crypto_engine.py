"""
crypto_engine.py — Sighax Simulator
Basado en la guía de MrJason005 (GBATemp, 2017) y el exploit original de SciresM.

──────────────────────────────────────────────────────────
El bootROM ARM9 verifica firmas RSA parseando el bloque resultante byte a byte.

Estructura del bloque descifrado (PKCS#1 v1.5):
  [00][01/02][FF..FF][00][30][31][30][0D][inner_block(13b)][04][20][correct_hash(32b)]
                                              ↑
                                   Este byte dice cuántos bytes saltar

Vulnerabilidad 1 — Padding type 0x02:
  El bootROM acepta 0x02 (sin padding). Facilita brute-force de firmas.

Vulnerabilidad 2 — Truco del puntero con el byte 0d:
  Manipulando el valor de 0d, el puntero aterriza en correct_hash.
  El parser cree estar en correct_hash, salta 32 bytes → acaba FUERA del bloque.
  El bootROM genera calculated_hash ahí y compara con lo que hay encima.
  Ambos son el mismo hash del mismo FIRM → SIEMPRE coinciden.
"""

import hashlib

HASH_LEN = 32  # SHA-256


class SignatureBlock:
    """
    Modela el bloque de firma tal como lo ve el parser del bootROM.
    """
    PADDING_TYPE_PADDED   = 0x01
    PADDING_TYPE_UNPADDED = 0x02
    INNER_BLOCK_REAL_LEN  = 13    # 0x0D
    TOTAL_BLOCK_SIZE      = 128

    def __init__(self, firmware_data: bytes, padding_type: int = 0x01,
                 inner_block_len_override: int = None):
        self.firmware_data        = firmware_data
        self.padding_type         = padding_type
        self.inner_block_len_byte = (inner_block_len_override
                                     if inner_block_len_override is not None
                                     else self.INNER_BLOCK_REAL_LEN)
        self._build()

    def _build(self):
        header = bytes([0x00, self.padding_type])

        if self.padding_type == 0x01:
            fixed_tail = 1 + 1 + 1 + 1 + 1 + self.INNER_BLOCK_REAL_LEN + 1 + 1 + HASH_LEN
            pad_len    = self.TOTAL_BLOCK_SIZE - len(header) - 1 - fixed_tail
            pad_len    = max(pad_len, 8)
            padding    = b'\xFF' * pad_len
            separator  = b'\x00'
        else:
            padding   = b''
            separator = b'\x00'

        inner_block  = bytes([0x06,0x09,0x60,0x86,0x48,0x01,0x65,
                               0x03,0x04,0x02,0x01,0x05,0x00])
        correct_hash = hashlib.sha256(self.firmware_data).digest()

        after_padding = bytes([
            0x30, 0x31, 0x30,
            self.inner_block_len_byte,
        ]) + inner_block + bytes([0x04, 0x20]) + correct_hash

        self.raw = (header + padding + separator + after_padding)[:self.TOTAL_BLOCK_SIZE]

        self.off_byte0         = 0
        self.off_byte1         = 1
        self.off_padding_start = 2
        self.off_padding_end   = len(header + padding) - 1 if padding else 1
        self.off_separator     = len(header + padding)
        self.off_30_1          = self.off_separator + 1
        self.off_31            = self.off_separator + 2
        self.off_30_2          = self.off_separator + 3
        self.off_0d            = self.off_separator + 4
        self.off_inner_start   = self.off_0d + 1
        self.off_inner_end     = self.off_inner_start + self.INNER_BLOCK_REAL_LEN
        self.off_04            = self.off_inner_end
        self.off_20            = self.off_inner_end + 1
        self.off_correct_hash  = self.off_inner_end + 2
        self.off_calc_hash     = self.off_correct_hash + HASH_LEN

        self.correct_hash    = correct_hash
        self.calculated_hash = correct_hash


class SighaxEngine:
    def get_key_summary(self) -> dict:
        return {
            'algorithm': 'RSA-2048',
            'hash':      'SHA-256',
            'padding':   'PKCS#1 v1.5',
            'e':         65537,
            'note':      'Clave privada d — solo Nintendo la conoce',
            'bits':      2048,
            'klen':      256,
            'N':         0xDEADBEEFCAFEBABE1337,
        }

    def bootrom_verify_correct(self, firmware: bytes) -> list[dict]:
        blk   = SignatureBlock(firmware, padding_type=0x01)
        steps = []

        steps.append({
            'id':    0,
            'title': 'Arranque del bootROM ARM9 — Carga del FIRM',
            'desc':  'Al encender la 3DS, el bootROM ARM9 es lo primero en ejecutarse.\n'
                     'Lee la imagen FIRM de la NAND y localiza el bloque de firma RSA.\n'
                     'Descifra la firma con la clave pública de Nintendo (hardcoded)\n'
                     'y parsea el resultado byte a byte.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                'FIRM magic':      '"FIRM" (0x46 49 52 4D)',
                'Firma':           '256 bytes (RSA-2048)',
                'Clave pública':   'Hardcoded en bootROM (no modificable)',
                'SHA-256(FIRM)':   hashlib.sha256(firmware).digest().hex().upper(),
            },
        })

        steps.append({
            'id':    1,
            'title': 'Descifrar firma: M = S^e mod N',
            'desc':  'El bootROM calcula M = S^e mod N con la clave pública de Nintendo.\n'
                     'El resultado M es el bloque de firma que se parsea byte a byte.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                'Operación':  'M = S^e mod N',
                'e':          '65537 (0x10001)',
                'Resultado':  'Bloque de 256 bytes → se parsea byte a byte',
            },
            'hex_block': blk.raw, 'highlight_bytes': {}, 'block_offsets': blk,
        })

        b0    = blk.raw[blk.off_byte0]
        b0_ok = (b0 == 0x00)
        steps.append({
            'id':    2,
            'title': f'Parser byte[0] = 0x{b0:02X} — Inicio de firma',
            'desc':  'Debe ser 0x00. Indica inicio de un bloque de firma RSA.',
            'ok':    b0_ok, 'tag': 'PASS' if b0_ok else 'FAIL', 'fatal': not b0_ok,
            'vals':  {'Esperado': '0x00', 'Recibido': f'0x{b0:02X}',
                      'Resultado': '✓ Correcto' if b0_ok else '✗ FIRM rechazado'},
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_byte0: 'header'}, 'block_offsets': blk,
            'pointer_at': blk.off_byte0,
        })
        if not b0_ok: return steps

        b1 = blk.raw[blk.off_byte1]
        padding_exists = (b1 == 0x01)
        steps.append({
            'id':    3,
            'title': f'Parser byte[1] = 0x{b1:02X} — Tipo de padding',
            'desc':  '0x01 = CON padding 0xFF (seguro)\n'
                     '0x02 = SIN padding (inseguro — ¡el bootROM lo acepta igualmente!)\n\n'
                     'Aceptar 0x02 es la Vulnerabilidad 1 del bootROM.',
            'ok':    True, 'tag': 'PASS',
            'vals':  {
                'Recibido':     f'0x{b1:02X} → CON padding (seguro)',
                '⚠️ Nota':      'El bootROM también acepta 0x02 — Vulnerabilidad 1',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_byte1: 'header'}, 'block_offsets': blk,
            'pointer_at': blk.off_byte1,
        })

        if padding_exists and blk.off_padding_start < blk.off_separator:
            pad_data = blk.raw[blk.off_padding_start:blk.off_separator]
            pad_ok   = all(b == 0xFF for b in pad_data)
            steps.append({
                'id':    4,
                'title': f'Parser bytes[2..{blk.off_separator-1}] — Padding 0xFF',
                'desc':  f'{len(pad_data)} bytes de padding. El parser verifica que todos sean 0xFF.\n'
                         'Avanza hasta encontrar el separador 0x00.',
                'ok':    pad_ok, 'tag': 'PASS' if pad_ok else 'FAIL', 'fatal': not pad_ok,
                'vals':  {
                    'Bytes de padding': str(len(pad_data)),
                    'Todos == 0xFF':    '✓ Sí' if pad_ok else '✗ No',
                },
                'hex_block': blk.raw,
                'highlight_bytes': {i: 'padding'
                                    for i in range(blk.off_padding_start, blk.off_separator)},
                'block_offsets': blk, 'pointer_at': blk.off_padding_start,
            })
            if not pad_ok: return steps

        sep    = blk.raw[blk.off_separator]
        sep_ok = (sep == 0x00)
        steps.append({
            'id':    5,
            'title': f'Parser byte[{blk.off_separator}] = 0x{sep:02X} — Separador',
            'desc':  'Separador 0x00. Fin del padding. Inicio de la estructura ASN.1.',
            'ok':    sep_ok, 'tag': 'PASS' if sep_ok else 'FAIL', 'fatal': not sep_ok,
            'vals':  {'Esperado': '0x00', 'Recibido': f'0x{sep:02X}'},
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_separator: 'separator'},
            'block_offsets': blk, 'pointer_at': blk.off_separator,
        })
        if not sep_ok: return steps

        b30a = blk.raw[blk.off_30_1]
        b31  = blk.raw[blk.off_31]
        b30b = blk.raw[blk.off_30_2]
        steps.append({
            'id':    6,
            'title': 'Parser 0x30, 0x31, 0x30 — Estructura ASN.1',
            'desc':  '0x30 verificado, 0x31 IGNORADO por el bootROM, 0x30 verificado.',
            'ok':    (b30a == 0x30 and b30b == 0x30), 'tag': 'PASS',
            'vals':  {
                f'[{blk.off_30_1}]=0x{b30a:02X}': '✓ Verificado',
                f'[{blk.off_31}]=0x{b31:02X}':   '⚠️ IGNORADO por bootROM',
                f'[{blk.off_30_2}]=0x{b30b:02X}': '✓ Verificado',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_30_1: 'der', blk.off_31: 'ignored', blk.off_30_2: 'der'},
            'block_offsets': blk, 'pointer_at': blk.off_30_1,
        })

        od_val = blk.raw[blk.off_0d]
        steps.append({
            'id':    7,
            'title': f'Parser byte[{blk.off_0d}] = 0x{od_val:02X} ({od_val}) — Longitud del inner block',
            'desc':  f'Este byte indica cuántos bytes va a saltar el parser (el inner block).\n'
                     f'Valor = 0x{od_val:02X} = {od_val} → saltará {od_val} bytes sin leerlos.\n\n'
                     f'⚠️ ESTE BYTE ES LA CLAVE DEL EXPLOIT SIGHAX.\n'
                     f'Manipulando su valor, el atacante puede mover el puntero del\n'
                     f'parser a cualquier posición del bloque.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                'Valor':          f'0x{od_val:02X} = {od_val} bytes (normal)',
                'Inner block':    f'OID SHA-256 — IGNORADO completamente',
                'Puntero tras skip': f'→ offset {blk.off_inner_start + od_val}',
                '⚠️ En sighax':   'Este byte se cambia para mover el puntero al correct_hash',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {
                blk.off_0d: 'key_byte',
                **{i: 'inner' for i in range(blk.off_inner_start, blk.off_inner_end)},
            },
            'block_offsets': blk, 'pointer_at': blk.off_0d,
        })

        b04 = blk.raw[blk.off_04] if blk.off_04 < len(blk.raw) else 0
        b20 = blk.raw[blk.off_20] if blk.off_20 < len(blk.raw) else 0
        steps.append({
            'id':    8,
            'title': 'Parser 0x04, 0x20 — También ignorados',
            'desc':  'Estos dos bytes también son ignorados. El parser avanza al correct_hash.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                f'[{blk.off_04}]=0x{b04:02X}': 'IGNORADO',
                f'[{blk.off_20}]=0x{b20:02X}': 'IGNORADO',
                'Siguiente':   f'→ correct_hash en offset {blk.off_correct_hash}',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_04: 'ignored', blk.off_20: 'ignored'},
            'block_offsets': blk, 'pointer_at': blk.off_04,
        })

        correct_hash    = blk.raw[blk.off_correct_hash:blk.off_correct_hash + HASH_LEN]
        calculated_hash = hashlib.sha256(firmware).digest()
        match           = (correct_hash == calculated_hash)
        steps.append({
            'id':    9,
            'title': 'Comparación: correct_hash vs calculated_hash',
            'desc':  'El bootROM genera SHA-256 del FIRM en tiempo real (calculated_hash)\n'
                     'y lo compara con el correct_hash del bloque de firma.\n'
                     'Si coinciden → FIRM auténtico.',
            'ok':    match, 'tag': 'VERIFIED ✓' if match else 'FAIL', 'fatal': not match,
            'vals':  {
                'correct_hash':    correct_hash.hex().upper(),
                'calculated_hash': calculated_hash.hex().upper(),
                'Resultado':       '✓ IDÉNTICOS — FIRM auténtico' if match else '✗ Rechazado',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {i: 'hash'
                                 for i in range(blk.off_correct_hash,
                                                blk.off_correct_hash + HASH_LEN)},
            'block_offsets': blk, 'pointer_at': blk.off_correct_hash,
        })
        return steps

    def forge_sighax(self, evil_firmware: bytes) -> tuple:
        # Calcular offsets del bloque forjado (sin padding, type=0x02)
        # usando un bloque temporal con el skip normal para conocer los offsets
        blk_temp    = SignatureBlock(evil_firmware, padding_type=0x02,
                                     inner_block_len_override=13)
        needed_skip = blk_temp.off_correct_hash - blk_temp.off_inner_start
        # Construir el bloque final con el skip manipulado
        blk_forged  = SignatureBlock(
            evil_firmware,
            padding_type=0x02,
            inner_block_len_override=needed_skip
        )
        info = {
            'original_0d':   13,
            'forged_0d':     needed_skip,
            'off_0d':        blk_forged.off_0d,
            'off_correct':   blk_forged.off_correct_hash,
            'off_calc':      blk_forged.off_calc_hash,
            'hash_len':      HASH_LEN,
            'evil_hash':     hashlib.sha256(evil_firmware).digest(),
            'skip_lands_at': blk_forged.off_inner_start + needed_skip,
        }
        return blk_forged, info

    def bootrom_verify_vulnerable(self, blk: SignatureBlock,
                                   evil_firmware: bytes,
                                   forge_info: dict) -> list[dict]:
        steps = []
        evil_hash  = forge_info['evil_hash']
        lands_at   = forge_info['skip_lands_at']
        outside    = lands_at + HASH_LEN

        steps.append({
            'id':    0,
            'title': 'Arranque con FIRM malicioso',
            'desc':  'El bootROM carga el FIRM modificado de la NAND.\n'
                     'Externamente idéntico a un FIRM legítimo.\n'
                     'El atacante ha brute-forceado una firma S tal que al descifrarla\n'
                     'con la clave pública de Nintendo produce el bloque manipulado.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                'FIRM magic':    '"FIRM" — sin modificar',
                'Payload':       'Código ARM9 del atacante (Boot9Strap, etc.)',
                'SHA-256(evil)': evil_hash.hex().upper(),
            },
        })

        steps.append({
            'id':    1,
            'title': 'Descifrar firma → bloque manipulado',
            'desc':  'El bootROM descifra la firma con la clave pública de Nintendo.\n'
                     'Obtiene el bloque diseñado por el atacante.\n\n'
                     'byte[1] = 0x02 → SIN padding (Vulnerabilidad 1).\n'
                     'Esto reduce enormemente el espacio de búsqueda para\n'
                     'brute-forcear la firma.',
            'ok':    True, 'tag': 'EXPLOIT', 'vuln': True,
            'vals':  {
                'byte[1]':  f'0x02 — SIN padding (Vulnerabilidad 1)',
                'Efecto':   'Brute-force de firma mucho más viable',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_byte1: 'vuln'}, 'block_offsets': blk,
        })

        b0 = blk.raw[blk.off_byte0]
        b1 = blk.raw[blk.off_byte1]
        steps.append({
            'id':    2,
            'title': f'Parser byte[0]=0x{b0:02X}, byte[1]=0x{b1:02X} — Sin padding',
            'desc':  'byte[0] = 0x00 ✓\n'
                     'byte[1] = 0x02 → el bootROM acepta esto.\n'
                     'Salta directamente al separador sin verificar padding 0xFF.',
            'ok':    True, 'tag': 'VULN', 'vuln': True,
            'vals':  {
                'byte[0]=0x00':  '✓ OK',
                'byte[1]=0x02':  '⚠️ Sin padding — bootROM acepta igualmente',
                'Padding:':      'SALTADO — ningún byte verificado',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {blk.off_byte0: 'header', blk.off_byte1: 'vuln'},
            'block_offsets': blk, 'pointer_at': blk.off_byte0,
        })

        steps.append({
            'id':    3,
            'title': 'Parser: separador, 0x30, 0x31(ignorado), 0x30',
            'desc':  'El parser avanza por la estructura ASN.1 normalmente.\n'
                     '0x31 ignorado como siempre.\n'
                     'Llega al byte crítico: el 0x0D modificado.',
            'ok':    True, 'tag': 'INFO',
            'vals':  {
                'Separador 0x00': '✓',
                '0x30':           '✓',
                '0x31':           'IGNORADO',
                '0x30':           '✓',
                'Siguiente:':     f'byte 0x{blk.raw[blk.off_0d]:02X} en offset {blk.off_0d} — ¡CLAVE!',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {
                blk.off_separator: 'separator',
                blk.off_30_1: 'der', blk.off_31: 'ignored', blk.off_30_2: 'der',
            },
            'block_offsets': blk, 'pointer_at': blk.off_separator,
        })

        od_val = blk.raw[blk.off_0d]
        steps.append({
            'id':    4,
            'title': f'⚠️ Parser byte[{blk.off_0d}] = 0x{od_val:02X} ({od_val}) — VULNERABILIDAD CENTRAL',
            'desc':  f'En un FIRM legítimo este byte es 0x0D (= 13).\n'
                     f'El atacante lo ha cambiado a 0x{od_val:02X} (= {od_val}).\n\n'
                     f'El parser va a saltar {od_val} bytes desde offset {blk.off_inner_start}.\n'
                     f'Aterriza en offset {lands_at}.\n\n'
                     f'Offset {lands_at} = inicio del campo correct_hash.\n'
                     f'El parser CREE que está en correct_hash.\n'
                     f'Pero en realidad está apuntando al CALCULATED_HASH.',
            'ok':    True, 'tag': 'VULN', 'vuln': True,
            'vals':  {
                'Valor legítimo':     '0x0D = 13 bytes',
                'Valor forjado':      f'0x{od_val:02X} = {od_val} bytes  ← MANIPULADO',
                'Salta desde':        f'offset {blk.off_inner_start}',
                'Aterriza en':        f'offset {lands_at} = inicio de correct_hash',
                '⚠️ ENGAÑO':          'Parser cree estar en correct_hash\n'
                                      'pero está en calculated_hash',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {
                blk.off_0d: 'key_byte',
                **{i: 'skipped' for i in range(blk.off_inner_start,
                                               min(blk.off_inner_start + od_val, len(blk.raw)))},
            },
            'block_offsets': blk, 'pointer_at': blk.off_0d, 'pointer_lands': lands_at,
        })

        steps.append({
            'id':    5,
            'title': f'Parser en offset {lands_at} — Cree que es correct_hash',
            'desc':  f'El parser ha aterrizado en offset {lands_at}.\n'
                     f'Cree que esto es el correct_hash (32 bytes).\n'
                     f'"Lee" esos 32 bytes como correct_hash.\n'
                     f'Luego salta 32 bytes para ir al calculated_hash...\n'
                     f'...pero aterriza en offset {outside},\n'
                     f'que está FUERA del bloque de firma.',
            'ok':    True, 'tag': 'EXPLOIT', 'vuln': True,
            'vals':  {
                '"correct_hash" leído': (blk.raw[lands_at:lands_at+HASH_LEN].hex().upper()
                                         if lands_at + HASH_LEN <= len(blk.raw)
                                         else evil_hash.hex().upper()),
                'Siguiente offset':     f'{outside} → FUERA del bloque de firma',
                'Zona de escritura':    'Memoria adyacente al bloque de firma',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {
                i: 'hash_confused'
                for i in range(lands_at, min(lands_at + HASH_LEN, len(blk.raw)))
            },
            'block_offsets': blk, 'pointer_at': lands_at,
        })

        steps.append({
            'id':    6,
            'title': f'bootROM escribe calculated_hash en offset {outside} — FUERA DEL BLOQUE',
            'desc':  f'El bootROM genera SHA-256 del FIRM malicioso en tiempo real\n'
                     f'y lo escribe en offset {outside} (fuera del bloque de firma).\n\n'
                     f'SHA-256(evil_FIRM) = {evil_hash.hex().upper()[:32]}...',
            'ok':    True, 'tag': 'EXPLOIT', 'vuln': True,
            'vals':  {
                'SHA-256(FIRM evil)':  evil_hash.hex().upper(),
                'Escrito en offset':   f'{outside} (fuera del bloque)',
                'Zona afectada':       'Memoria contigua al bloque de firma',
            },
            'hex_block': blk.raw, 'highlight_bytes': {}, 'block_offsets': blk,
        })

        steps.append({
            'id':    7,
            'title': '💀 Comparación — SIEMPRE COINCIDE',
            'desc':  'El bootROM compara:\n'
                     f'  • "correct_hash" (offset {lands_at}):  SHA-256 del FIRM evil\n'
                     f'  • "calculated_hash" (offset {outside}): SHA-256 del FIRM evil\n\n'
                     'SON EL MISMO HASH DEL MISMO FIRM.\n'
                     'La comparación SIEMPRE tiene éxito, para CUALQUIER FIRM.\n\n'
                     '→ El bootROM acepta el FIRM malicioso como completamente auténtico.\n'
                     '→ ARM9 ejecuta código del atacante con privilegios máximos (ring-1).',
            'ok':    True, 'tag': 'PWNED', 'vuln': True,
            'vals':  {
                '"correct_hash"':     evil_hash.hex().upper(),
                '"calculated_hash"':  evil_hash.hex().upper(),
                'Coinciden':          '✓ SIEMPRE — para cualquier FIRM',
                'Acceso obtenido':    'ARM9 ring-1 · NAND R/W · OTP dump · AES keys',
                'RESULTADO':          '💀 FIRM MALICIOSO ACEPTADO — Sistema comprometido',
            },
            'hex_block': blk.raw,
            'highlight_bytes': {
                i: 'hash'
                for i in range(lands_at, min(lands_at + HASH_LEN, len(blk.raw)))
            },
            'block_offsets': blk,
        })

        return steps

    def hex_dump(self, data: bytes, cols: int = 16) -> str:
        lines = []
        for i in range(0, len(data), cols):
            chunk = data[i:i+cols]
            h = ' '.join(f'{b:02X}' for b in chunk)
            a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04X}  {h:<{cols*3}}  {a}')
        return '\n'.join(lines)