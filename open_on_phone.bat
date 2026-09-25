@echo off
title AegisShield - Auto Launch On Phone via USB
echo ===================================================
echo   Launching AegisShield on your Samsung Phone...
echo ===================================================
cd /d "%~dp0\host"
python launch_usb.py
pause
