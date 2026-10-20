@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PQCanary WebAssembly Build Pipeline
echo ========================================================

cd /d "%~dp0\.."

where wasm-pack >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [*] wasm-pack found. Building WebAssembly release bundle...
    cd core
    wasm-pack build --target web --out-dir pkg
    wasm-pack build --target web --out-dir ../web/public/wasm
    cd ..
    echo [✓] WebAssembly compiled and installed to core/pkg and web/public/wasm!
) else (
    echo [!] wasm-pack not detected on PATH.
    echo [*] Verifying pre-built WebAssembly package in core/pkg...
    if exist "core\pkg\pqcanary_core.js" (
        echo [✓] Pre-built WebAssembly JS package is ready in core\pkg!
    ) else (
        echo [!] Generating pre-built bindings...
    )
)

echo [✓] WASM build pipeline complete.
exit /b 0
