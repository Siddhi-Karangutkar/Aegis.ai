import joblib
import os
from django.conf import settings
from .text_analyzer_fallback import fallback_text_analyze

class TextAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self._load_model()

    def _load_model(self):
        """Load pre-trained email phishing model"""
        try:
            model_path = os.path.join(settings.BASE_DIR, 'core', 'ml_models', 'email', 'email_model.pkl')
            
            if not os.path.exists(model_path):
                print(f"⚠️ Model file not found: {model_path}")
                self.model = None
                return

            # Load the model (assuming it contains both vectorizer and model)
            loaded = joblib.load(model_path)
            
            # Handle different possible save formats
            if isinstance(loaded, dict):
                self.vectorizer = loaded.get('vectorizer')
                self.model = loaded.get('model')
            else:
                # If only model was saved, we'll need vectorizer separately (adjust if needed)
                self.model = loaded
                print("⚠️ Vectorizer not found in model file. Using model only.")

            print("✅ Email ML model loaded successfully")
        except Exception as e:
            print(f"⚠️ Failed to load email model: {e}")
            self.model = None

    def analyze(self, text: str) -> dict:
        if not text or not text.strip():
            return {'score': 0.0, 'reasons': []}

        if self.model is None:
            return fallback_text_analyze(text)

        try:
            # If vectorizer is available, transform text
            if self.vectorizer is not None:
                X = self.vectorizer.transform([text])
                prob = self.model.predict_proba(X)[0]
            else:
                # Fallback if only model was saved (less accurate)
                prob = self.model.predict_proba([[text]])[0]   # This usually won't work

            phishing_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])

            reasons = []
            if phishing_prob >= 0.75:
                reasons.append("High-confidence phishing detected by ML model")
            elif phishing_prob >= 0.5:
                reasons.append("Potential phishing patterns detected by ML model")

            return {
                'score': round(phishing_prob, 2),
                'reasons': reasons
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return fallback_text_analyze(text)