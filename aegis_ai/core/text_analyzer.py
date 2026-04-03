import re

class TextAnalyzer:
    def analyze(self, text: str) -> dict:
        if not text:
            return {'score': 0.0, 'reasons': []}

        score = 0.0
        reasons = []

        text_lower = text.lower()

        # Urgency indicators
        urgency_words = ['immediately', 'urgent', 'suspended', 'verify now', 'account locked',
                        'suspension', 'action required', 'limited time']
        for word in urgency_words:
            if word in text_lower:
                score += 0.25
                reasons.append("Urgency language detected")

        # Credential phishing phrases
        credential_phrases = ['password', 'otp', 'pin', 'login credentials', 'verify your identity']
        for phrase in credential_phrases:
            if phrase in text_lower:
                score += 0.20
                reasons.append("Request for credentials or OTP detected")

        # Impersonation
        if any(bank in text_lower for bank in ['bank', 'paypal', 'amazon', 'microsoft', 'google']):
            score += 0.15
            reasons.append("Impersonation of trusted brand")

        score = min(score, 1.0)

        return {'score': score, 'reasons': reasons}