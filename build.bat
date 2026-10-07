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

REM Single self-contained .exe (--onefile): Python runtime, Tcl/Tk and all
REM DLLs are packed inside; no external files are needed next to the exe.
REM --onefile unpacks to a temp folder at startup (a second or two slower),
REM and some antivirus products flag onefile bootloaders - whitelist if needed.
python -m PyInstaller ^
    --noconfirm ^
    --onefile ^
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
echo Executable: dist\NetAppAuditViewer.exe
echo Single file - copy dist\NetAppAuditViewer.exe anywhere to run it.
echo ===========================================================

endlocal
