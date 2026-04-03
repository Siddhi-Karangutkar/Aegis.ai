import re
from urllib.parse import urlparse

class URLAnalyzer:
    def analyze(self, urls: list) -> dict:
        if not urls:
            return {'score': 0.0, 'reasons': []}

        max_score = 0.0
        all_reasons = []

        for url in urls:
            score, reasons = self._analyze_single_url(url)
            if score > max_score:
                max_score = score
            all_reasons.extend(reasons)

        return {
            'score': round(max_score, 2),
            'reasons': list(set(all_reasons))   # unique reasons
        }

    def _analyze_single_url(self, url: str) -> tuple:
        score = 0.0
        reasons = []

        parsed = urlparse(url)

        # 1. Length
        if len(url) > 80:
            score += 0.30
            reasons.append("Unusually long URL")

        # 2. Hyphens & dots
        if url.count('-') > 3:
            score += 0.25
            reasons.append("Multiple hyphens in URL")
        if url.count('.') > 4:
            score += 0.20
            reasons.append("Too many subdomains")

        # 3. IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc):
            score += 0.40
            reasons.append("Uses raw IP address")

        # 4. Suspicious keywords (capped)
        suspicious_keywords = ['login', 'verify', 'secure', 'update', 'bank', 'alert', 'otp']
        keyword_hits = sum(1 for kw in suspicious_keywords if kw in url.lower())
        keyword_score = min(keyword_hits * 0.15, 0.45)   # hard cap
        score += keyword_score
        if keyword_hits > 0:
            reasons.append(f"Suspicious keyword(s) in URL ({keyword_hits} hits)")

        return min(score, 1.0), reasons