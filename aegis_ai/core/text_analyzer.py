import re

class TextAnalyzer:
    def analyze(self, text: str) -> dict:
        if not text or not text.strip():
            return {'score': 0.0, 'reasons': []}

        text_lower = text.lower()
        score = 0.0
        reasons = []

        # Category-based scoring (no more unbounded accumulation)
        # Each category has a hard cap

        # 1. Urgency / Pressure
        urgency_words = ['immediately', 'urgent', 'suspended', 'verify now', 'account locked',
                         'suspension', 'action required', 'limited time', 'expires soon']
        if any(word in text_lower for word in urgency_words):
            score += 0.35
            reasons.append("Urgency / pressure language detected")

        # 2. Credential / OTP phishing
        credential_phrases = ['password', 'otp', 'pin', 'login credentials', 'verify your identity',
                              'confirm your account', 'enter your details']
        if any(phrase in text_lower for phrase in credential_phrases):
            score += 0.35
            reasons.append("Request for credentials / OTP detected")

        # 3. Brand impersonation
        brands = ['bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook']
        if any(brand in text_lower for brand in brands):
            score += 0.30
            reasons.append("Impersonation of trusted brand")

        return {
            'score': round(min(score, 1.0), 2),
            'reasons': reasons
        }