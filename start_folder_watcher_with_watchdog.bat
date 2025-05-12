@echo off
REM Start the Folder Watcher Python script with self-protection (auto-restart)
cd /d "%~dp0%"
REM Start all components only if scheduled scan is enabled
python conditional_startup.py