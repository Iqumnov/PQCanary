@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PQCanary Enterprise Multi-Platform Build Pipeline
echo   Target: Windows EXE, MSI, Web, WASM, and Microservice
echo ========================================================

cd /d "%~dp0\.."

echo.
echo [1/5] Building Native CLI & MCP Server...
cargo build --release --bin pqcanary --bin pqcanary-mcp
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile native Rust binaries!
    exit /b %ERRORLEVEL%
)
echo [✓] Binaries generated at target\release\pqcanary.exe and pqcanary-mcp.exe

echo.
echo [2/5] Building WebAssembly & Browser Bundles...
call scripts\build_wasm.bat

echo.
echo [3/5] Building SolidStart Web UI Frontend...
cd web
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile web application!
    cd ..
    exit /b %ERRORLEVEL%
)
cd ..
echo [✓] Web distribution generated at web\.output\public

echo.
echo [4/5] Building Tauri Desktop Application (MSI & NSIS EXE)...
cd web
call npm run tauri:build
if %ERRORLEVEL% NEQ 0 (
    echo [!] Tauri desktop installer build finished with code %ERRORLEVEL%.
) else (
    echo [✓] Desktop MSI & NSIS installers generated in web\src-tauri\target\release\bundle\
)
cd ..

echo.
echo [5/5] Packaging Summary:
echo   - CLI:            target\release\pqcanary.exe
echo   - MCP Server:     target\release\pqcanary-mcp.exe
echo   - Web Assets:     web\.output\public
echo   - Pre-built WASM: core\pkg\pqcanary_core.js
echo.
echo ========================================================
echo   PQCanary Build Complete!
echo ========================================================
exit /b 0
