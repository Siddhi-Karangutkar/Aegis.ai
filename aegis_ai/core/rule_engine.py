class RuleEngine:
    FREE_EMAIL_DOMAINS = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'protonmail.com', 'icloud.com', 'aol.com', 'yandex.com'
    }

    def analyze(self, data: dict) -> dict:
        score = 0.0
        reasons = []

        sender_email = data.get('sender_email', '').lower()
        sender_name = data.get('sender_name', '').lower()

        if sender_email and '@' in sender_email:
            domain = sender_email.split('@')[-1]

            # Rule 1: Company name + free email domain (classic phishing)
            if domain in self.FREE_EMAIL_DOMAINS and any(word in sender_name for word in ['bank', 'support', 'security', 'admin', 'paypal', 'amazon']):
                score += 0.45
                reasons.append("Company name used with free email domain (phishing pattern)")

            # Rule 2: Too many URLs
            if len(data.get('urls', [])) > 3:
                score += 0.30
                reasons.append("Excessive number of URLs in single email")

        return {
            'score': round(min(score, 1.0), 2),
            'reasons': reasons
        }