@echo off
REM Start Redis server
start "" "C:\Redis\redis-server.exe"
REM Wait a few seconds for Redis to initialize
ping 127.0.0.1 -n 4 > nul
REM Activate virtual environment and start the antivirus Flask app
call "venv\Scripts\activate.bat"
python app.py
pause
