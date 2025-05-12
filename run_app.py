import sys
import os
import ctypes
import subprocess
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('app_runner')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        # Re-run the script as administrator
        try:
            script = os.path.abspath(__file__)
            params = ' '.join([script] + sys.argv[1:])
            subprocess.run(f'powershell Start-Process python -ArgumentList "{params}" -Verb RunAs', shell=True)
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to run as admin: {str(e)}")
            sys.exit(1)

def start_dns_server():
    try:
        # Start DNS server in a new process
        subprocess.Popen(['python', 'dns_server.py'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        logger.info("DNS server started successfully")
    except Exception as e:
        logger.error(f"Failed to start DNS server: {str(e)}")
        sys.exit(1)

def start_flask_app():
    try:
        # Start Flask app in a new process
        subprocess.Popen(['python', 'app.py'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        logger.info("Flask app started successfully")
    except Exception as e:
        logger.error(f"Failed to start Flask app: {str(e)}")
        sys.exit(1)

def main():
    # First, run as admin if needed
    run_as_admin()
    
    # Then start both servers
    logger.info("Starting services...")
    
    # Start DNS server first since it needs admin privileges
    start_dns_server()
    
    # Wait a moment for DNS server to start
    time.sleep(2)
    
    # Start Flask app
    start_flask_app()
    
    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down services...")

if __name__ == "__main__":
    main()
