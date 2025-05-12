import numpy as np
from advanced_threat_detector import ThreatDetectionModel
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO)

# Initialize the threat detection model
detector = ThreatDetectionModel()

# Define sample features for each threat type
FEATURES = {
    'malware': [
        'file_size', 'entropy', 'imports_count', 'sections_count',
        'exports_count', 'digital_signature', 'packer_used',
        'api_calls_count', 'network_connections', 'registry_changes'
    ],
    'ddos': [
        'packet_rate', 'bytes_per_second', 'connection_duration',
        'syn_count', 'ack_count', 'rst_count', 'flags', 'ttl',
        'window_size', 'payload_size'
    ],
    'exfiltration': [
        'data_size', 'encryption_used', 'compression_ratio',
        'connection_count', 'time_window', 'protocol_type',
        'destination_port', 'data_rate', 'packet_size',
        'connection_duration'
    ],
    'lateral_movement': [
        'login_attempts', 'failed_logins', 'successful_logins',
        'time_between_logins', 'ip_changes', 'user_changes',
        'connection_attempts', 'protocol_changes', 'port_changes',
        'authentication_changes'
    ]
}

def generate_sample_data(threat_type: str, n_samples: int = 1000):
    """Generate sample data for training."""
    n_features = len(FEATURES[threat_type])
    X = np.random.rand(n_samples, n_features)
    y = np.random.randint(0, 2, n_samples)
    return X, y

def train_all_models():
    """Train all threat detection models."""
    for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
        try:
            logging.info(f"Training {threat_type} model...")
            X, y = generate_sample_data(threat_type)
            success = detector.train_model(threat_type, X, y)
            if success:
                logging.info(f"Successfully trained and saved {threat_type} model")
            else:
                logging.error(f"Failed to train {threat_type} model")
        except Exception as e:
            logging.error(f"Error training {threat_type} model: {e}")

if __name__ == "__main__":
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Train all models
    train_all_models()
    
    # Verify models were saved
    for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
        model_path = os.path.join('models', f"{threat_type}_model.pkl")
        if os.path.exists(model_path):
            logging.info(f"Model saved: {model_path}")
        else:
            logging.error(f"Model not saved: {model_path}")
