import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import logging
from typing import Tuple
from pathlib import Path

from advanced_threat_detector import ThreatDetectionModel

# Set up logging
logging.basicConfig(level=logging.INFO)

class RealDataTrainer:
    def __init__(self, data_dir='data', model_dir='models'):
        self.data_dir = Path(data_dir)
        self.model_dir = Path(model_dir)
        self.detector = ThreatDetectionModel(model_dir=model_dir)
        
    def load_labeled_data(self, threat_type: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load labeled data for a specific threat type."""
        try:
            data_dir = self.data_dir / 'labeled'
            data_files = list(data_dir.glob(f"{threat_type}_*.json"))
            
            if not data_files:
                logging.warning(f"No labeled data found for {threat_type}")
                return None, None
            
            features = []
            labels = []
            
            for file_path in data_files:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    features.append(list(data['features'].values()))
                    labels.append(data['label'])
            
            return np.array(features), np.array(labels)
            
        except Exception as e:
            logging.error(f"Error loading labeled data: {e}")
            return None, None
            
    def train_model(self, threat_type: str):
        """Train a model with real data."""
        try:
            X, y = self.load_labeled_data(threat_type)
            if X is None or y is None:
                logging.error(f"No data available for {threat_type}")
                return False
                
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train model
            success = self.detector.train_model(threat_type, X_train, y_train)
            if not success:
                return False
                
            # Evaluate model
            y_pred = self.detector.models[threat_type].predict(X_test)
            report = classification_report(y_test, y_pred, zero_division=0)
            logging.info(f"{threat_type} model evaluation:\n{report}")
            
            # Save model and components
            self.detector.save_model(threat_type)
            
            return True
            
        except Exception as e:
            logging.error(f"Error training {threat_type} model: {e}")
            return False
            
    def train_all_models(self):
        """Train all threat detection models with real data."""
        threat_types = ['malware', 'ddos', 'exfiltration', 'lateral_movement']
        
        for threat_type in threat_types:
            try:
                logging.info(f"Training {threat_type} model with real data...")
                success = self.train_model(threat_type)
                if success:
                    logging.info(f"Successfully trained {threat_type} model")
                else:
                    logging.error(f"Failed to train {threat_type} model")
                    
            except Exception as e:
                logging.error(f"Error in training process: {e}")

if __name__ == "__main__":
    # Initialize trainer
    trainer = RealDataTrainer()
    
    # Train all models with real data
    trainer.train_all_models()
    
    # Verify models were saved
    for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
        model_path = trainer.model_dir / f"{threat_type}_model.pkl"
        if model_path.exists():
            logging.info(f"Model saved: {model_path}")
        else:
            logging.error(f"Model not saved: {model_path}")
