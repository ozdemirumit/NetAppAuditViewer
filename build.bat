@echo off
REM ===========================================================
REM NetApp Audit Viewer - PyInstaller build script
REM ===========================================================

setlocal

REM Clean previous builds
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

REM Install PyInstaller if missing
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found, installing...
    python -m pip install --upgrade pyinstaller
    if errorlevel 1 (
        echo ERROR: Could not install PyInstaller. Check your network/proxy settings.
        exit /b 1
    )
)

echo.
echo Building...
echo.

REM Using --onedir (default) for antivirus compatibility and faster startup.
REM If you want a single .exe, add --onefile to the line below.
python -m PyInstaller ^
    --noconfirm ^
    --windowed ^
    --name "NetAppAuditViewer" ^
    --clean ^
    netapp_audit_viewer.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed.
    exit /b 1
)

echo.
echo ===========================================================
echo Build complete.
echo Executable: dist\NetAppAuditViewer\NetAppAuditViewer.exe
echo Zip the folder for distribution.
echo ===========================================================

endlocal
