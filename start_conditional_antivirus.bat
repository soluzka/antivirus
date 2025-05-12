@echo off
REM Start all antivirus components using conditional_startup.py
REM Get the directory of this BAT file (should be antivirus folder)
cd /d "%~dp0"
start "" "app.py"
REM The window will remain open as long as the components are running.
