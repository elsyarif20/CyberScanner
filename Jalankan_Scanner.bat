@echo off
title CyberScanner Pro Launcher
echo Menyiapkan environment...
:: Mengecek apakah admin (Opsional namun disarankan untuk Scapy)
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Menjalankan dengan hak akses Administrator.
) else (
    echo PERINGATAN: Jalankan file ini sebagai Administrator agar Scan ARP berfungsi!
    pause
)

cd /d "%~dp0"
echo Membuka Dashboard Streamlit...
streamlit run main.py
pause