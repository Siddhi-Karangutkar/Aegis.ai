import logging
from .text_analyzer_fallback import fallback_text_analyze

logger = logging.getLogger('aegis.text')


class TextAnalyzer:
    """
    Text/email phishing analyzer.
    Uses pure-Python heuristic rules — no ML dependencies required.
    """

    def __init__(self):
        logger.info("[text_analyzer.py] TextAnalyzer initialized (heuristic mode)")

    def analyze(self, text: str) -> dict:
        if not text or not text.strip():
            logger.info("[text_analyzer.py] Empty text received — returning score 0.0")
            return {'score': 0.0, 'reasons': []}

        logger.info(f"[text_analyzer.py] Analyzing text ({len(text)} chars)")
        logger.info(f"[text_analyzer.py] → Triggering: core/text_analyzer_fallback.py → fallback_text_analyze()")
        result = fallback_text_analyze(text)
        logger.info(f"[text_analyzer.py] ← Result: score={result['score']}, reasons={result['reasons']}")
        return result