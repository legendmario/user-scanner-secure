# 🛡️ User Scanner Secure - OSINT & Digital Footprint Auditor (v2.0 Hardened)

[![Security Hardened](https://img.shields.io/badge/security-OPSEC%20v2.0-green.svg)](#seguridad-y-opsec)
[![SAST Audit](https://img.shields.io/badge/SAST-Bandit%20Passing-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Dependencies](https://img.shields.io/badge/Dependencies-pip--audit%20Clean-blue.svg)](https://pypi.org/project/pip-audit/)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Entorno de ejecución seguro, auditado y optimizado para la suite **User-Scanner**, actualizado con los estándares de ciberseguridad vigentes.

---

## 📌 Contexto: ¿Por qué Sherlock y Holehe quedaron obsoletas?

| Herramienta | Función Principal | Estado Actual / Problemática |
| :--- | :--- | :--- |
| **Sherlock** | Reconocimiento de usernames | Dependiente de respuestas HTTP estáticas (`200 OK` vs `404`). Incompatible con Single Page Applications (SPAs) modernas y WAFs (Cloudflare/Akamai), resultando en una alta tasa de **falsos positivos**. |
| **Holehe** | Reconocimiento de emails | Consultaba APIs de registro y recuperación. Bloqueada por defensas modernas: CAPTCHAs invisibles (Cloudflare Turnstile, reCAPTCHA v3), tokens CSRF dinámicos y rate-limiting agresivo. Módulos en su mayoría inoperativos. |
| **User-Scanner** | **Suite Unificada (Email + Usernames)** | **Activa y mantenida.** Soporta **+2,720 vectores**, evasión WAF mediante **TLS Fingerprinting (`curl_cffi` / `httpx`)**, emulación de APIs móviles, integración con **MCP (Model Context Protocol)** y soporte nativo de proxies. |

---

## 🛡️ Mejoras de Seguridad Incorporadas en este Proyecto (v2.0)

Este repositorio no es un simple script, sino un entorno fortificado (*Hardened*) con controles de ciberseguridad:

1. **Pre-flight OPSEC Check (`--check-ip`):**
   - Comprobación en tiempo real de la dirección IP pública de salida antes de iniciar el escaneo masivo, verificando si el proxy está activo o alertando en caso de exposición directa de IP.
2. **Cadena de Custodia con Hashing SHA-256:**
   - Cada reporte exportado en `./results/` genera automáticamente su firma criptográfica `.sha256` para garantizar que la evidencia recopilada no fue alterada tras la auditoría.
3. **Sanitización Estricta contra Inyecciones:**
   - Validación por expresiones regulares en usernames y emails.
   - Ejecución mediante listas seguras en `subprocess.run` (sin `shell=True`), previniendo inyección de comandos en el sistema anfitrión.
4. **Protección Anti-Fuga de Datos (`.gitignore`):**
   - El directorio `results/`, archivos de salida y listas de objetivos están aislados para impedir su publicación accidental en GitHub.
5. **Auditoría Continua en GitHub Actions (`security.yml`):**
   - Análisis estático de seguridad (SAST) con **Bandit**.
   - Escaneo semanal automatizado de vulnerabilidades conocidas (CVEs) en dependencias con **pip-audit**.
6. **Aislamiento Docker sin Privilegios:**
   - Contenedor con usuario no-root (`appuser`), aislando totalmente la ejecución de la máquina anfitriona.

---

## 🚀 Instalación y Puesta en Marcha

### Requisitos
- Python 3.10 o superior.

### 1. Clonar el repositorio
```bash
git clone https://github.com/TU-USUARIO/user-scanner-secure.git
cd user-scanner-secure
```

### 2. Crear y activar entorno virtual
```bash
# En Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

# En Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar dependencias auditadas
```bash
pip install -r requirements.txt
```

---

## 💻 Uso del Wrapper Fortificado (`secure_runner.py`)

### 1. Comprobar OPSEC / IP de salida
```bash
# Verificación directa:
python secure_runner.py --check-ip

# Verificación a través de un proxy:
python secure_runner.py --check-ip -p "http://127.0.0.1:8080"
```

### 2. Auditar un Nombre de Usuario
```bash
python secure_runner.py -u tu_nombre_de_usuario
```

### 3. Auditar con Proxy (Recomendado para OPSEC)
```bash
python secure_runner.py -u tu_nombre_de_usuario -p "socks5://127.0.0.1:9050"
```

### 4. Auditar un Correo Electrónico
```bash
python secure_runner.py -e ejemplo@dominio.com
```

### 5. Escaneos Masivos desde Archivo Seguro
```bash
python secure_runner.py --uf lista_usuarios.txt
```

*Los resultados se almacenan en `./results/` en formato `.json` junto con su archivo de integridad `.sha256`.*

---

## 🐳 Ejecución con Docker (Máximo Aislamiento)

```bash
# Construir la imagen aislada
docker build -t user-scanner-secure .

# Ejecutar auditoría montando solo el directorio de resultados
docker run --rm -v ${PWD}/results:/app/results user-scanner-secure -u usuario_test
```

---

## ⚖️ Descargo de Responsabilidad (Disclaimer)

Este proyecto está diseñado exclusivamente para propósitos de **ciberseguridad defensiva, investigación ética y auditorías de huella digital personal con autorización explícita**. No debe utilizarse para actividades no autorizadas, invasión de la privacidad ni hostigamiento.
