@echo off
title AegisShield Host Engine
echo ===================================================
echo   Starting AegisShield Mobile Security Host Daemon
echo ===================================================
cd /d "%~dp0\host"

python -m pip install -r requirements.txt
python host_daemon.py
pause
