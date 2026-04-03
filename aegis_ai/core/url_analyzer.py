import re
from urllib.parse import urlparse

class URLAnalyzer:
    def analyze(self, urls: list) -> dict:
        if not urls:
            return {'score': 0.0, 'reasons': []}

        total_score = 0.0
        all_reasons = []

        for url in urls:
            score, reasons = self._analyze_single_url(url)
            total_score += score
            all_reasons.extend(reasons)

        avg_score = min(total_score / len(urls), 1.0)

        return {
            'score': avg_score,
            'reasons': list(set(all_reasons))  # unique reasons
        }

    def _analyze_single_url(self, url: str) -> tuple:
        score = 0.0
        reasons = []

        parsed = urlparse(url)

        # Feature 1: Length
        if len(url) > 80:
            score += 0.25
            reasons.append("Unusually long URL")

        # Feature 2: Number of hyphens and dots
        hyphen_count = url.count('-')
        dot_count = url.count('.')
        if hyphen_count > 3:
            score += 0.25
            reasons.append("Multiple hyphens in URL (suspicious)")
        if dot_count > 4:
            score += 0.20
            reasons.append("Too many subdomains")

        # Feature 3: IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
            score += 0.30
            reasons.append("URL uses IP address instead of domain")

        # Feature 4: Suspicious keywords
        suspicious_keywords = ['login', 'verify', 'secure', 'update', 'bank', 'alert']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                score += 0.15
                reasons.append(f"Suspicious keyword in URL: '{keyword}'")

        return min(score, 1.0), reasons