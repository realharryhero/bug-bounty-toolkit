@echo off
REM Virtual Browser Startup Script for Windows
REM This script starts the virtualized browser environment

echo ================================================
echo   Virtual Browser Environment
echo ================================================
echo.

REM Check if Docker is installed
where docker >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Docker is not installed.
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if Docker is running
docker info >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Docker daemon is not running.
    echo Please start Docker Desktop first.
    pause
    exit /b 1
)

echo Building virtual browser environment...
docker-compose build

echo.
echo Starting virtual browser...
docker-compose up -d

echo.
echo Waiting for services to start...
timeout /t 5 /nobreak >nul

REM Check if container is running
docker ps | find "virtual-browser" >nul
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================
    echo   Virtual browser is running!
    echo ================================================
    echo.
    echo Browser Access:
    echo   Open your web browser and navigate to:
    echo   http://localhost:6080
    echo.
    echo VNC Access (optional^):
    echo   VNC Server: localhost:5901
    echo   Password: vncpassword
    echo.
    echo Available Browsers:
    echo   - Firefox
    echo   - Chromium
    echo.
    echo Management Commands:
    echo   Stop:    docker-compose down
    echo   Restart: docker-compose restart
    echo   Logs:    docker-compose logs -f
    echo.
    echo ================================================
) else (
    echo Error: Failed to start virtual browser.
    echo Check logs with: docker-compose logs
    pause
    exit /b 1
)

pause
