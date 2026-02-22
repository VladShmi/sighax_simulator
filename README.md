# SIGHAX Simulator

Simulador educativo del exploit **SIGHAX** del bootROM ARM9 de Nintendo 3DS.  
Este proyecto muestra de forma visual y práctica cómo funciona la verificación criptográfica legítima y cómo se aprovecha la vulnerabilidad que permitió la ejecución de código no autorizado.

---

## Características

- Interfaz gráfica moderna basada en **PyQt6**
- Simulación de:
  - ✅ Verificación legítima de firmas RSA-2048
  - ⚡ Proceso de explotación SIGHAX
- Implementación didáctica de:
  - RSA-2048
  - PKCS#1 v1.5
- Motor criptográfico modular y desacoplado
- Diseño visual estilo herramienta de análisis

---

## 🎯 Objetivo

Este proyecto está diseñado con fines **educativos y de investigación** para entender:

- El proceso de arranque seguro (secure boot)
- La verificación de firmas en el bootROM ARM9
- La vulnerabilidad que permitió el exploit SIGHAX
- Conceptos prácticos de criptografía aplicada
- Fallos en validación de firmas RSA en sistemas embebidos

No interactúa con hardware real ni modifica dispositivos.

---

## 🧠 Contexto Técnico

El exploit SIGHAX se basa en una implementación defectuosa de la verificación RSA en el bootROM ARM9, donde la validación de PKCS#1 v1.5 no era estricta, permitiendo la construcción de firmas especialmente manipuladas que eran aceptadas como válidas.

Este simulador reproduce:

- Flujo de verificación legítima
- Flujo de validación vulnerable
- Comparación entre comportamiento seguro vs vulnerable

---

## 📦 Requisitos

- Python 3.10 o superior
- PyQt6

Instalación:

```bash
pip install PyQt6
```

---

## 🚀 Ejecución

```bash
python main.py
```

## 🛡 Aviso Legal

Este proyecto es exclusivamente para:

- Educación
- Investigación en seguridad
- Comprensión de vulnerabilidades históricas

No promueve el uso indebido de exploits ni la modificación de dispositivos comerciales.
