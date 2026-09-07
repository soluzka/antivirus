from utils.paths import get_resource_path
import os
import sys
import time
import subprocess
import logging

logger = logging.getLogger(__name__)

def watchdog_restart(target_cmd):
    """
    Restart the antivirus process if it is killed (basic watchdog).
    SECURITY: Validate target_cmd to prevent command injection
    """
    # SECURITY: Validate target command path
    if not target_cmd or not isinstance(target_cmd, str):
        raise ValueError("target_cmd must be a non-empty string")
    
    # Prevent path traversal attacks
    if '..' in target_cmd or target_cmd.startswith('/') or ':' in target_cmd.replace(':', '', 1).replace(':', ''):
        raise ValueError("Invalid target command path")
    
    # --- Windows subprocess window suppression ---
    if sys.platform == 'win32':
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
    else:
        DETACHED_PROCESS = 0
        CREATE_NO_WINDOW = 0
    
    max_restarts = 10
    restart_count = 0
    
    while restart_count < max_restarts:
        try:
            # SECURITY: Use absolute path and validate executable
            target_path = get_resource_path(target_cmd)
            if not os.path.exists(target_path):
                logger.error(f"Target executable not found: {target_path}")
                break
            
            proc = subprocess.Popen(
                [target_path], 
                creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, 
                stdin=subprocess.DEVNULL, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )  # nosem; nosec B603
            proc.wait()
            restart_count += 1
            logger.warning(f"Process restarted {restart_count}/{max_restarts} times")
            time.sleep(1)  # Short delay before restart
        except Exception as e:
            logger.error(f"Watchdog error: {e}")
            break
    
    if restart_count >= max_restarts:
        logger.error("Max restart attempts reached, watchdog stopped")