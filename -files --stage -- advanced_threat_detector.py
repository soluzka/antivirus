import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import logging
from typing import Dict, List, Tuple
import time
from datetime import datetime
import json

class ThreatDetectionModel:
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.models = {}
        self.scalers = {}
        self.pcas = {}
        self.model_loaded = False
        
    def initialize_models(self, force_reload=False):
        """Initialize and load ML models for different threat types.
        
        Args:
            force_reload: If True, will reload models even if they were previously loaded
        """
        if self.model_loaded and not force_reload:
            return
            
        try:
            # Check numpy version compatibility
            import numpy as np
            if np.__version__ < '1.21.0':
                logging.warning("Warning: Using numpy version < 1.21.0 may cause compatibility issues with saved models")
                
            # Load models and their components
            for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
                try:
                    # Load the model
                    model_path = os.path.join(self.model_dir, f'{threat_type}_model.pkl')
                    self.models[threat_type] = joblib.load(model_path)
                    
                    # Load the scaler
                    scaler_path = os.path.join(self.model_dir, f'{threat_type}_scaler.pkl')
                    self.scalers[threat_type] = joblib.load(scaler_path)
                    
                    # Load the PCA
                    pca_path = os.path.join(self.model_dir, f'{threat_type}_pca.pkl')
                    self.pcas[threat_type] = joblib.load(pca_path)
                    
                    logging.info(f"Successfully loaded {threat_type} model and components")
                except FileNotFoundError:
                    logging.warning(f"No saved {threat_type} model found, creating new model")
                    if threat_type == 'malware':
                        self.models[threat_type] = self.create_malware_model()
                    elif threat_type == 'ddos':
                        self.models[threat_type] = self.create_ddos_model()
                    elif threat_type == 'exfiltration':
                        self.models[threat_type] = self.create_exfiltration_model()
                    elif threat_type == 'lateral_movement':
                        self.models[threat_type] = self.create_lateral_movement_model()
                        
                    # Create new scaler and PCA
                    self.scalers[threat_type] = StandardScaler()
                    self.pcas[threat_type] = PCA(n_components=0.95)
                    
                    # Save newly created model and components
                    joblib.dump(self.models[threat_type], model_path)
                    joblib.dump(self.scalers[threat_type], scaler_path)
                    joblib.dump(self.pcas[threat_type], pca_path)
                    logging.info(f"Created and saved new {threat_type} model and components")
                    
            self.model_loaded = True
        except Exception as e:
            logging.error(f"Error initializing models: {str(e)}")
            raise
        
    def initialize_models(self):
        """Initialize and load saved ML models for different threat types."""
        self.models = {}
        self.scalers = {}
        self.pcas = {}
        
        # Load models and their components
        for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
            try:
                # Load the model
                model_path = os.path.join(self.model_dir, f'{threat_type}_model.pkl')
                self.models[threat_type] = joblib.load(model_path)
                
                # Load the scaler
                scaler_path = os.path.join(self.model_dir, f'{threat_type}_scaler.pkl')
                self.scalers[threat_type] = joblib.load(scaler_path)
                
                # Load the PCA
                pca_path = os.path.join(self.model_dir, f'{threat_type}_pca.pkl')
                self.pcas[threat_type] = joblib.load(pca_path)
                
                logging.info(f"Successfully loaded {threat_type} model and components")
            except FileNotFoundError:
                logging.warning(f"No saved {threat_type} model found, creating new model")
                if threat_type == 'malware':
                    self.models[threat_type] = self.create_malware_model()
                elif threat_type == 'ddos':
                    self.models[threat_type] = self.create_ddos_model()
                elif threat_type == 'exfiltration':
                    self.models[threat_type] = self.create_exfiltration_model()
                elif threat_type == 'lateral_movement':
                    self.models[threat_type] = self.create_lateral_movement_model()
                
                # Initialize scaler and PCA
                self.scalers[threat_type] = StandardScaler()
                self.pcas[threat_type] = PCA(n_components=0.95)
                
                # Create synthetic data for initial training
                X = np.random.rand(100, 10)  # 100 samples with 10 features
                y = np.zeros(100)
                y[:20] = 1  # 20% positive samples
                
                # Fit scaler and PCA
                X_scaled = self.scalers[threat_type].fit_transform(X)
                X_pca = self.pcas[threat_type].fit_transform(X_scaled)
                
                # Train the model
                self.models[threat_type].fit(X_pca, y)
                
                # Save the models
                joblib.dump(self.models[threat_type], model_path)
                joblib.dump(self.scalers[threat_type], scaler_path)
                joblib.dump(self.pcas[threat_type], pca_path)
                
                logging.info(f"Created and saved new {threat_type} model")
            except Exception as e:
                logging.error(f"Failed to initialize {threat_type} model: {e}")
                raise
            
    def create_malware_model(self):
        """Create model for malware detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
    def create_ddos_model(self):
        """Create model for DDoS detection."""
        return Pipeline([
            ('scaler', MinMaxScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', OneClassSVM(
                kernel='rbf',
                nu=0.01,
                gamma='auto'
            ))
        ])
        
    def create_exfiltration_model(self):
        """Create model for data exfiltration detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=42
            ))
        ])
        
    def create_lateral_movement_model(self):
        """Create model for lateral movement detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', RandomForestClassifier(
                n_estimators=150,
                max_depth=12,
                min_samples_split=4,
                random_state=42,
              