@echo off
REM Start the antivirus server
cd /d "%~dp0"
start "" "app.py"
REM The window will remain open as long as the server is running.
