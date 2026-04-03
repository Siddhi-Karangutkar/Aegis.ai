import os
import logging
from django.conf import settings
from .url_analyzer_fallback import fallback_url_analyze

logger = logging.getLogger('aegis.url')

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

class URLAnalyzer:
    """
    URL phishing analyzer.
    Attempts to use ML via url_model.pkl if available.
    Falls back to pure-Python heuristics on failure.
    """

    def __init__(self):
        self.model = None
        self.use_ml = False
        self._load_models()

    def _load_models(self):
        if not HAS_JOBLIB:
            logger.info("[url_analyzer.py] joblib not found, defaulting to heuristic mode")
            return

        try:
            model_path = os.path.join(settings.BASE_DIR, 'core', 'ml_models', 'url', 'url_model.pkl')
            if not os.path.exists(model_path):
                logger.warning(f"[url_analyzer.py] ML model not found at {model_path}. Using fallback.")
                return

            # The pkl might contain a pipeline or dictionary
            loaded = joblib.load(model_path)
            self.model = loaded
            self.use_ml = True
            logger.info("✅ URL ML model loaded successfully")
        except Exception as e:
            logger.error(f"⚠️ URL ML model failed to load: {e}. Using fallback rules.")
            self.model = None
            self.use_ml = False

    def analyze(self, urls: list) -> dict:
        if not urls:
            logger.info("[url_analyzer.py] No URLs to analyze — returning score 0.0")
            return {'score': 0.0, 'reasons': []}

        logger.info(f"[url_analyzer.py] Analyzing {len(urls)} URL(s): {urls[:3]}")

        # Try ML prediction if model is loaded
        if self.use_ml and self.model is not None:
            try:
                max_score = 0.0
                all_reasons = []

                for url in urls:
                    # Model usually expects a 2D array or list depending on pipeline
                    # If it's a pipeline, passing [url] is typical
                    prob = self.model.predict_proba([url])[0]
                    # Assuming positive malicious case is at index 1
                    malicious_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])
                    
                    if malicious_prob > max_score:
                        max_score = malicious_prob
                    
                    if malicious_prob >= 0.6:
                        all_reasons.append(f"ML model flagged URL with confidence {malicious_prob:.2f}")
                
                logger.info(f"[url_analyzer.py] ← ML Result: score={max_score:.2f}, reasons={all_reasons}")
                return {'score': round(max_score, 2), 'reasons': list(set(all_reasons))}
            except Exception as e:
                logger.error(f"[url_analyzer.py] ML prediction failed: {e}. Falling back to heuristics.")

        # Fallback
        logger.info(f"[url_analyzer.py] → Triggering: core/url_analyzer_fallback.py → fallback_url_analyze()")
        result = fallback_url_analyze(urls)
        logger.info(f"[url_analyzer.py] ← Heuristic Result: score={result['score']}, reasons={result['reasons']}")
        return result