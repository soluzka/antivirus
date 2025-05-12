import os
import logging
from sklearn.ensemble import IsolationForest
import numpy as np
import joblib

class MalwareDetector:
    def __init__(self):
        self.logger = logging.getLogger('malware_detector')
        self.model = self.load_model()
        
    def load_model(self):
        """Load the ML model."""
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'model', 'malware_detector_model.pkl')
            if not os.path.exists(model_path):
                self.logger.warning("Model file not found, creating new model")
                return self.create_model()
                
            return joblib.load(model_path)
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return self.create_model()
            
    def create_model(self):
        """Create a new ML model."""
        model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        # Train on some initial data (this should be done with real malware/benign samples)
        # For now, we'll just create some dummy data
        X = np.random.randn(1000, 5)  # 5 features
        model.fit(X)
        return model
        
    def predict(self, file_paths):
        """Predict if files are malicious."""
        try:
            features = self.extract_features(file_paths)
            return self.model.predict(features)
        except Exception as e:
            self.logger.error(f"Error in prediction: {str(e)}")
            return [1]  # Default to non-malicious if error occurs
            
    def get_anomaly_score(self, file_path):
        """Get anomaly score for a file."""
        try:
            features = self.extract_features([file_path])
            return self.model.decision_function(features)[0]
        except Exception as e:
            self.logger.error(f"Error getting anomaly score: {str(e)}")
            return 0.0
            
    def extract_features(self, file_paths):
        """Extract features from files."""
        features = []
        for file_path in file_paths:
            try:
                # Extract basic features
                size = os.path.getsize(file_path)
                mtime = os.path.getmtime(file_path)
                ctime = os.path.getctime(file_path)
                path_length = len(os.path.dirname(file_path))
                is_executable = os.path.splitext(file_path)[1] in ['.exe', '.dll', '.sys']
                
                features.append([
                    size,
                    mtime,
                    ctime,
                    path_length,
                    int(is_executable)
                ])
            except Exception as e:
                self.logger.error(f"Error extracting features for {file_path}: {str(e)}")
                features.append([0, 0, 0, 0, 0])  # Default features
        
        return np.array(features)

# Create a singleton instance
detector = MalwareDetector()
