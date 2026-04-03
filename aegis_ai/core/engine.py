import logging

from .text_analyzer import TextAnalyzer
from .url_analyzer import URLAnalyzer
from .rule_engine import RuleEngine
from .preprocessor import extract_urls_from_text
from .fusion import fuse_scores

logger = logging.getLogger('aegis.engine')


class PhishingEngine:
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.rule_engine = RuleEngine()

    def detect(self, input_data: dict, request_id: str = '----') -> dict:
        tag = f"[REQ-{request_id}]"
        email_text = input_data.get('email_text', '')
        urls = input_data.get('urls', [])

        # Auto-extract URLs from text/PDFs
        logger.info(f"{tag} [engine.py] Running preprocessor → extract_urls_from_text()")
        extracted_urls = extract_urls_from_text(email_text)
        all_urls = list(set(urls + extracted_urls))
        has_urls = len(all_urls) > 0
        logger.info(f"{tag} [engine.py] Total URLs for analysis: {len(all_urls)}")

        # ── Text Analyzer ──
        logger.info(f"{tag} [engine.py] → Triggering: core/text_analyzer.py → TextAnalyzer.analyze()")
        text_result = self.text_analyzer.analyze(email_text)
        logger.info(f"{tag} [engine.py] ← Text score: {text_result['score']} | Reasons: {len(text_result['reasons'])}")

        # ── URL Analyzer ──
        logger.info(f"{tag} [engine.py] → Triggering: core/url_analyzer.py → URLAnalyzer.analyze()")
        url_result = self.url_analyzer.analyze(all_urls)
        logger.info(f"{tag} [engine.py] ← URL score: {url_result['score']} | Reasons: {len(url_result['reasons'])}")

        # ── Rule Engine ──
        logger.info(f"{tag} [engine.py] → Triggering: core/rule_engine.py → RuleEngine.analyze()")
        rule_result = self.rule_engine.analyze(input_data)
        logger.info(f"{tag} [engine.py] ← Rule score: {rule_result['score']} | Reasons: {len(rule_result['reasons'])}")

        # ── Fusion ──
        logger.info(f"{tag} [engine.py] → Triggering: core/fusion.py → fuse_scores()")
        final_score = fuse_scores(
            text_result['score'],
            url_result['score'],
            rule_result['score'],
            has_urls=has_urls
        )
        logger.info(f"{tag} [engine.py] ← Fused score: {final_score}")

        # Verdict mapping aligned with 30/50 thresholds
        if final_score > 0.50:
            verdict = "malicious"
        elif final_score >= 0.30:
            verdict = "suspicious"
        else:
            verdict = "benign"

        all_reasons = text_result['reasons'] + url_result['reasons'] + rule_result['reasons']

        logger.info(f"{tag} [engine.py] Final verdict: {verdict} ({final_score})")

        return {
            "verdict": verdict,
            "confidence_score": final_score,
            "reasons": all_reasons[:8],
            "breakdown": {
                "text_score": text_result['score'],
                "url_score": url_result['score'],
                "rule_score": rule_result['score']
            }
        }