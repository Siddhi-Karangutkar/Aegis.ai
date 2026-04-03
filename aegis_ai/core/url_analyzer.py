import joblib
import os
from django.conf import settings

class URLAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self._load_models()

    def _load_models(self):
        """Load pre-trained Character TF-IDF + Random Forest"""
        try:
            model_path = os.path.join(settings.BASE_DIR, 'core', 'ml_models', 'url', 'randomforest_model.pkl')
            vectorizer_path = os.path.join(settings.BASE_DIR, 'core', 'ml_models', 'url', 'char_tfidf_vectorizer.pkl')

            self.vectorizer = joblib.load(vectorizer_path)
            self.model = joblib.load(model_path)
            print("✅ URL ML model loaded successfully")
        except Exception as e:
            print(f"⚠️ URL ML model failed to load: {e}. Using fallback rules.")
            self.model = None

    def analyze(self, urls: list) -> dict:
        if not urls:
            return {'score': 0.0, 'reasons': []}

        if self.model is None:
            # Fallback to current heuristic logic
            from .url_analyzer_fallback import fallback_url_analyze
            return fallback_url_analyze(urls)

        max_score = 0.0
        all_reasons = []

        for url in urls:
            try:
                X = self.vectorizer.transform([url])
                prob = self.model.predict_proba(X)[0]
                malicious_prob = prob[1]   # assuming class 1 = malicious

                if malicious_prob > max_score:
                    max_score = malicious_prob

                if malicious_prob > 0.6:
                    all_reasons.append(f"ML model flagged URL as malicious (confidence: {malicious_prob:.2f})")
            except:
                pass

        return {
            'score': round(max_score, 2),
            'reasons': list(set(all_reasons))
        }