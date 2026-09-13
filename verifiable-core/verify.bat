@echo off
rem Double-click to open the BoreLine verifier menu.
cd /d "%~dp0"
python verify_invoices.py --menu
echo.
pause
