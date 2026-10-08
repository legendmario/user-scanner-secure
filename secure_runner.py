#!/usr/bin/env python3
"""
Secure Runner for User-Scanner (OSINT & Digital Footprint Auditing)
Actualizado con validación estricta de inputs, verificación pre-vuelo de OPSEC/IP
y generación de hashes de integridad SHA-256 para cadena de custodia.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# Configurar codificación segura para consola en Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Constantes de validación
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\.\-]{1,64}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
PROXIES_REGEX = re.compile(r"^(http|https|socks5|socks4)://[a-zA-Z0-9.:@_-]+$")

BANNER = r"""
======================================================================
  [USER-SCANNER SECURE RUNNER v2.0] - OSINT & FOOTPRINT AUDITOR
  Seguridad Hardened | Control OPSEC | Hashes SHA-256 | Anti-Leak
======================================================================
"""


def validate_username(username: str) -> bool:
    if not USERNAME_REGEX.match(username):
        raise ValueError(
            f"[!] Error de seguridad: Nombre de usuario inválido '{username}'. Solo caracteres alfanuméricos, guiones, puntos y barras bajas (máx 64 caracteres)."
        )
    return True


def validate_email(email: str) -> bool:
    if not EMAIL_REGEX.match(email):
        raise ValueError(
            f"[!] Error de seguridad: Formato de correo electrónico inválido '{email}'."
        )
    return True


def validate_proxy(proxy_str: str) -> bool:
    if not PROXIES_REGEX.match(proxy_str):
        raise ValueError(
            f"[!] Error de configuración: Formato de proxy inválido '{proxy_str}'. Ejemplo: http://127.0.0.1:8080 o socks5://127.0.0.1:9050"
        )
    return True


def safe_file_path(filepath: str) -> Path:
    """Evita path traversal y valida que el archivo de entrada exista."""
    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"[!] Archivo no encontrado: {filepath}")
    return path


def setup_results_dir() -> Path:
    """Crea y asegura el directorio local de resultados."""
    base_dir = Path(__file__).parent.resolve()
    results_dir = base_dir / "results"
    results_dir.mkdir(exist_ok=True)
    return results_dir


def check_egress_ip(proxy: str = None) -> str:
    """
    Verificación pre-vuelo de OPSEC: comprueba la IP de salida visible hacia el exterior
    para confirmar si el tráfico está o no anonimizado.
    """
    url = "https://api.ipify.org"
    try:
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=8) as response:
                return response.read().decode("utf-8").strip()
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as response:
                return response.read().decode("utf-8").strip()
    except Exception as ex:
        return f"[!] No se pudo determinar IP externa ({ex})"


def calculate_sha256(filepath: Path) -> str:
    """Calcula el hash SHA-256 de un archivo para garantizar integridad y cadena de custodia."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Wrapper seguro de alta disponibilidad para User-Scanner con controles OPSEC, integridad y auditoría."
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-u", "--username", help="Nombre de usuario a auditar")
    group.add_argument("-e", "--email", help="Correo electrónico a auditar")
    group.add_argument("--uf", "--user-file", help="Archivo con lista de nombres de usuario")
    group.add_argument("--ef", "--email-file", help="Archivo con lista de correos electrónicos")

    parser.add_argument("-p", "--proxy", help="Proxy opcional (ej: socks5://127.0.0.1:9050 o http://127.0.0.1:8080)")
    parser.add_argument("-m", "--module", help="Módulo o plataforma específica (ej: github, twitter)")
    parser.add_argument("--check-ip", action="store_true", help="Comprobar IP pública de salida y salir")
    parser.add_argument("--no-opsec-warning", action="store_true", help="Omitir advertencia de OPSEC")

    args = parser.parse_args()

    # Si solo se solicita verificación de IP
    if args.check_ip:
        if args.proxy:
            validate_proxy(args.proxy)
            print(f"[*] Verificando IP a través del proxy: {args.proxy}")
        else:
            print("[*] Verificando IP pública directa...")
        ip = check_egress_ip(args.proxy)
        print(f"[+] IP detectada hacia el exterior: {ip}\n")
        return

    if not any([args.username, args.email, args.uf, args.ef]):
        parser.error("Debes especificar un objetivo: -u, -e, --uf, --ef (o usar --check-ip).")

    # Control OPSEC y verificación previa de IP
    if args.proxy:
        validate_proxy(args.proxy)
        print(f"[*] Validando conexión de proxy ({args.proxy})...")
        egress_ip = check_egress_ip(args.proxy)
        print(f"[+] OPSEC OK: IP de salida enmascarada a través de proxy -> {egress_ip}\n")
    elif not args.no_opsec_warning:
        print("[!] AVISO DE OPSEC CRITICO:")
        print("    No has configurado un proxy. Los escaneos saldrán directamente desde tu IP.")
        direct_ip = check_egress_ip()
        print(f"    Tu IP pública actual visible es: {direct_ip}")
        print("    Para prevenir bloqueos o rastreo, usa: --proxy 'http://...' o una VPN.\n")

    # Detección del ejecutable
    cli_exec = shutil.which("user-scanner")
    if cli_exec:
        cmd = [cli_exec]
    else:
        cmd = [sys.executable, "-m", "user_scanner"]

    # Validación de inputs y preparación de nombres de archivo
    results_dir = setup_results_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.username:
        validate_username(args.username)
        cmd.extend(["-u", args.username])
        output_prefix = f"user_{args.username}_{timestamp}"
    elif args.email:
        validate_email(args.email)
        cmd.extend(["-e", args.email])
        sanitized_email = re.sub(r"[^a-zA-Z0-9]", "_", args.email)
        output_prefix = f"email_{sanitized_email}_{timestamp}"
    elif args.uf:
        user_file = safe_file_path(args.uf)
        cmd.extend(["-uf", str(user_file)])
        output_prefix = f"bulk_users_{timestamp}"
    elif args.ef:
        email_file = safe_file_path(args.ef)
        cmd.extend(["-ef", str(email_file)])
        output_prefix = f"bulk_emails_{timestamp}"

    if args.proxy:
        cmd.extend(["-p", args.proxy])

    if args.module:
        cmd.extend(["-m", args.module])

    output_file = results_dir / f"{output_prefix}.json"
    cmd.extend(["-o", str(output_file)])

    print(f"[+] Iniciando auditoría con User-Scanner...")
    print(f"[+] Destino de resultados: {output_file}\n")

    try:
        # Ejecución protegida sin shell=True (previene inyección de comandos)
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            print(f"\n[OK] Auditoría finalizada exitosamente.")
            print(f"[OK] Resultados guardados de forma segura en: {output_file}")

            # Generar hash SHA-256 de integridad para cadena de custodia
            if output_file.exists():
                file_hash = calculate_sha256(output_file)
                hash_file = results_dir / f"{output_prefix}.sha256"
                hash_file.write_text(f"{file_hash} *{output_file.name}\n", encoding="utf-8")
                print(f"[OK] Hash de integridad generado: {file_hash}")
                print(f"[OK] Registro de hash guardado en: {hash_file}")
        else:
            print(f"\n[!] El comando finalizó con código de salida {result.returncode}.")
            print("[!] Si el módulo 'user_scanner' no está instalado, ejecuta:")
            print("    pip install -r requirements.txt")
    except FileNotFoundError:
        print("[!] No se encontró el intérprete de Python o el ejecutable.")
    except Exception as ex:
        print(f"[!] Error inesperado durante la ejecución: {ex}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileNotFoundError) as err:
        print(f"\n{err}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.")
        sys.exit(0)
