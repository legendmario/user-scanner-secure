@echo off
chcp 65001 >nul
title User-Scanner Secure - Auditor de Huella Digital
color 0A

:: Ubicarse en el directorio del script
cd /d "%~dp0"

echo ======================================================================
echo   [🛡️ USER-SCANNER SECURE] - ASISTENTE DE EJECUCIÓN FÁCIL
echo ======================================================================
echo.

:: 1. Verificar si Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo [X] Error: Python no está instalado o no se encuentra en el PATH.
    echo     Por favor instala Python desde https://www.python.org/
    pause
    exit /b 1
)

:: 2. Verificar o crear entorno virtual
if not exist "venv\Scripts\activate.bat" (
    echo [*] Creando entorno virtual aislado (venv)...
    python -m venv venv
    if errorlevel 1 (
        echo [X] Error al crear el entorno virtual.
        pause
        exit /b 1
    )
    echo [*] Instalando dependencias de seguridad y escáner...
    call venv\Scripts\activate.bat
    pip install --upgrade pip
    pip install -r requirements.txt
    echo [OK] Entorno preparado correctamente.
    echo.
) else (
    call venv\Scripts\activate.bat
)

:MENU
cls
echo ======================================================================
echo   [🛡️ USER-SCANNER SECURE] - MENÚ PRINCIPAL
echo ======================================================================
echo.
echo   1. Comprobar mi IP de salida y estado OPSEC
echo   2. Auditar un Nombre de Usuario (Username)
echo   3. Auditar un Correo Electrónico (Email)
echo   4. Auditar un Usuario usando un Proxy (Recomendado)
echo   5. Abrir carpeta de Resultados (results)
echo   6. Salir
echo.
set /p OPCION="Elige una opción (1-6): "

if "%OPCION%"=="1" goto OPSEC
if "%OPCION%"=="2" goto USERNAME
if "%OPCION%"=="3" goto EMAIL
if "%OPCION%"=="4" goto PROXY
if "%OPCION%"=="5" goto OPEN_RESULTS
if "%OPCION%"=="6" goto SALIR

echo [!] Opción no válida.
timeout /t 2 >nul
goto MENU

:OPSEC
cls
echo [*] Ejecutando comprobación de IP pública...
python secure_runner.py --check-ip
echo.
pause
goto MENU

:USERNAME
cls
echo.
set /p TARGET_USER="Introduce el nombre de usuario a auditar (ej: juan_perez): "
if "%TARGET_USER%"=="" goto MENU
echo.
python secure_runner.py -u %TARGET_USER%
echo.
pause
goto MENU

:EMAIL
cls
echo.
set /p TARGET_EMAIL="Introduce el correo electrónico a auditar (ej: correo@gmail.com): "
if "%TARGET_EMAIL%"=="" goto MENU
echo.
python secure_runner.py -e %TARGET_EMAIL%
echo.
pause
goto MENU

:PROXY
cls
echo.
set /p TARGET_USER="Introduce el nombre de usuario: "
set /p PROXY_URL="Introduce el Proxy (ej: http://127.0.0.1:8080 o socks5://127.0.0.1:9050): "
if "%TARGET_USER%"=="" goto MENU
echo.
python secure_runner.py -u %TARGET_USER% -p %PROXY_URL%
echo.
pause
goto MENU

:OPEN_RESULTS
start "" "%~dp0results"
goto MENU

:SALIR
exit /b 0
