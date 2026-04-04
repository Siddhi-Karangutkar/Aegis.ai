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


def _is_pipeline_model(model) -> bool:
    """
    Returns True only if the loaded model is a full sklearn Pipeline
    (i.e. it includes a vectorizer step and can accept raw URL strings directly).
    A bare LogisticRegression/SVC without a vectorizer cannot be used as-is.
    """
    return hasattr(model, 'named_steps') or hasattr(model, 'steps')


class URLAnalyzer:
    """
    URL phishing analyzer.
    Uses an sklearn Pipeline (vectorizer + classifier) from url_model.pkl when available.
    The model MUST be a full Pipeline that accepts raw URL strings.
    A bare LogisticRegression without its vectorizer will be skipped — it cannot
    transform raw strings into the 528k-dimensional TF-IDF space it was trained on.
    Falls back to pure-Python heuristics in all other cases.

    To fix the ML path permanently: retrain and save the model as:
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5))),
            ('clf',   LogisticRegression(max_iter=1000))
        ])
        pipeline.fit(X_train_urls, y_train)
        joblib.dump(pipeline, 'core/ml_models/url/url_model.pkl')
    """

    def __init__(self):
        self.model = None
        self.use_ml = False
        self._load_models()

    def _load_models(self):
        if not HAS_JOBLIB:
            logger.info("[url_analyzer.py] joblib not found — using heuristic mode")
            return

        try:
            model_path = os.path.join(settings.BASE_DIR, 'core', 'ml_models', 'url', 'url_model.pkl')
            if not os.path.exists(model_path):
                logger.warning(f"[url_analyzer.py] url_model.pkl not found at {model_path} — using heuristics")
                return

            loaded = joblib.load(model_path)

            if not _is_pipeline_model(loaded):
                # The saved model is a bare classifier with no vectorizer attached.
                # It cannot transform raw URL strings into features.
                # Heuristic fallback will handle all URL analysis until this is fixed.
                logger.warning(
                    "[url_analyzer.py] url_model.pkl is a bare classifier (no vectorizer pipeline) "
                    "and cannot accept raw URL strings. Using heuristics instead. "
                    "Fix: resave as a full sklearn Pipeline([('tfidf', ...), ('clf', ...)])."
                )
                return

            self.model = loaded
            self.use_ml = True
            logger.info("[url_analyzer.py] \u2705 URL ML pipeline loaded successfully")

        except Exception as e:
            logger.error(f"[url_analyzer.py] \u26a0\ufe0f Failed to load url_model.pkl: {e} — using heuristics")
            self.model = None
            self.use_ml = False

    def analyze(self, urls: list) -> dict:
        if not urls:
            return {'score': 0.0, 'reasons': []}

        logger.info(f"[url_analyzer.py] Analyzing {len(urls)} URL(s): {urls[:3]}")

        if self.use_ml and self.model is not None:
            try:
                max_score = 0.0
                all_reasons = []

                for url in urls:
                    prob = self.model.predict_proba([url])[0]
                    # Resolve which index corresponds to the malicious/phishing class
                    classes = list(getattr(self.model, 'classes_', []))
                    malicious_idx = 1  # safe default
                    for i, cls in enumerate(classes):
                        if str(cls).lower() in ('phishing', 'bad', 'malicious', '1'):
                            malicious_idx = i
                            break
                    malicious_prob = float(prob[malicious_idx])

                    if malicious_prob > max_score:
                        max_score = malicious_prob
                    if malicious_prob >= 0.6:
                        all_reasons.append(f"ML model flagged URL with {malicious_prob:.0%} confidence")

                logger.info(f"[url_analyzer.py] \u2190 ML result: score={max_score:.2f}, reasons={all_reasons}")
                return {'score': round(max_score, 2), 'reasons': list(set(all_reasons))}

            except Exception as e:
                logger.error(f"[url_analyzer.py] ML prediction failed: {e} — falling back to heuristics")

        # Heuristic fallback (always active until a full Pipeline model is provided)
        result = fallback_url_analyze(urls)
        logger.info(f"[url_analyzer.py] \u2190 Heuristic result: score={result['score']}, reasons={result['reasons']}")
        return result