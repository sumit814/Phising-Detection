import joblib
import numpy as np
from typing import Dict, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

class PhishingModel:
    """Handles ML-based phishing detection"""
    
    def __init__(self, model_path: str = None, vectorizer_path: str = None):
        self.model = self._load_model(model_path)
        self.vectorizer = self._load_vectorizer(vectorizer_path)
        
    def _load_model(self, path: str) -> Optional[RandomForestClassifier]:
        """Load pre-trained model"""
        try:
            return joblib.load(path) if path else None
        except:
            return None
            
    def _load_vectorizer(self, path: str) -> Optional[TfidfVectorizer]:
        """Load feature vectorizer"""
        try:
            return joblib.load(path) if path else None
        except:
            return None
            
    def predict(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Make prediction based on features"""
        if not self.model or not self.vectorizer:
            return {'error': 'Model not loaded'}
            
        try:
            # Convert features to string representation
            features_str = ' '.join([f'{k}_{v}' for k,v in features.items()])
            X = self.vectorizer.transform([features_str])
            
            proba = self.model.predict_proba(X)[0]
            return {
                'prediction': self.model.predict(X)[0],
                'probability_phishing': proba[1],
                'probability_benign': proba[0]
            }
        except Exception as e:
            return {'error': str(e)}
            
    def train(self, X, y):
        """Train new model (for retraining)"""
        self.vectorizer = TfidfVectorizer()
        X_transformed = self.vectorizer.fit_transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_transformed, y)
        
        return self.model.score(X_transformed, y)
