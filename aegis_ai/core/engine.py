from .text_analyzer import TextAnalyzer
from .url_analyzer import URLAnalyzer
from .rule_engine import RuleEngine
from .preprocessor import extract_urls_from_text
from .fusion import fuse_scores

class PhishingEngine:
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.rule_engine = RuleEngine()

    def detect(self, input_data: dict) -> dict:
        email_text = input_data.get('email_text', '')
        urls = input_data.get('urls', [])

        # Auto-extract URLs from text (including PDFs)
        extracted_urls = extract_urls_from_text(email_text)
        all_urls = list(set(urls + extracted_urls))

        # Run all three engines
        text_result = self.text_analyzer.analyze(email_text)
        url_result = self.url_analyzer.analyze(all_urls)
        rule_result = self.rule_engine.analyze(input_data)

        # Fusion
        final_score = fuse_scores(
            text_result['score'],
            url_result['score'],
            rule_result['score']
        )

        # Determine verdict
        if final_score >= 0.75:
            verdict = "malicious"
        elif final_score >= 0.45:
            verdict = "suspicious"
        else:
            verdict = "benign"

        # Collect all reasons
        all_reasons = (
            text_result['reasons'] +
            url_result['reasons'] +
            rule_result['reasons']
        )

        return {
            "verdict": verdict,
            "confidence_score": final_score,
            "reasons": all_reasons[:8],  # limit reasons
            "breakdown": {
                "text_score": round(text_result['score'], 2),
                "url_score": round(url_result['score'], 2),
                "rule_score": round(rule_result['score'], 2)
            }
        }