# PQCanary Universal Installer for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PQCanary Enterprise Post-Quantum Security Platform" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "Compiling and installing PQCanary via Cargo..." -ForegroundColor Green
    cargo install --path ./cli --bin pqcanary --locked
    Write-Host "OK: Installed successfully to $env:USERPROFILE\.cargo\bin\pqcanary.exe" -ForegroundColor Green
} else {
    Write-Host "ERROR: Rust toolchain (cargo) not found. Please install Rust from https://rustup.rs" -ForegroundColor Red
    exit 1
}

Write-Host "SUCCESS: Run 'pqcanary --help' to get started." -ForegroundColor Green
