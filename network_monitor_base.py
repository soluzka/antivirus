from utils.paths import get_resource_path
import os
import psutil
import time
import logging
import redis
from redis.exceptions import ConnectionError
import threading

class NetworkMonitor:
    def __init__(self, use_redis=False):
        self.running = False
        self.thread = None
        self.use_redis = use_redis
        self.redis_client = None
        self.network_info = {}
        self.logger = logging.getLogger('network_monitor')
        self.setup_logging()
        
        if self.use_redis:
            try:
                self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
                self.redis_client.ping()
                self.logger.info("Successfully connected to Redis")
            except ConnectionError:
                self.logger.warning("Redis not available, using in-memory storage")
                self.use_redis = False

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_monitor.log'),
                logging.StreamHandler()
            ]
        )

    def start(self):
        """Start the network monitoring thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.monitor_network, daemon=True)
            self.thread.start()
            self.logger.info("Network monitoring started")

    def stop(self):
        """Stop the network monitoring thread."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.logger.info("Network monitoring stopped")

    def is_running(self):
        """Check if network monitoring is active."""
        return self.running

    def monitor_network(self):
        """Monitor network activity and store information."""
        while self.running:
            try:
                # Get network connections
                connections = []
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cwd']):
                    try:
                        proc_connections = proc.connections()
                        if proc_connections:
                            connections.extend(proc_connections)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Store network information
                self.network_info = {
                    'connections': len(connections),
                    'timestamp': time.time()
                }

                # Store in Redis if available
                if self.use_redis and self.redis_client:
                    self.redis_client.set('network_info', json.dumps(self.network_info))

            except Exception as e:
                self.logger.error(f"Error monitoring network: {str(e)}")

            time.sleep(1)  # Check every second

    def get_network_info(self):
        """Get current network information."""
        if self.use_redis and self.redis_client:
            try:
                data = self.redis_client.get('network_info')
                if data:
                    return json.loads(data)
            except Exception as e:
                self.logger.error(f"Error getting network info from Redis: {str(e)}")
        return self.network_info
