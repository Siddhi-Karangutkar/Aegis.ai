class RuleEngine:
    def analyze(self, data: dict) -> dict:
        score = 0.0
        reasons = []

        sender_email = data.get('sender_email', '')
        sender_name = data.get('sender_name', '')

        # Rule 1: Sender name vs email mismatch (common in phishing)
        if sender_email and sender_name:
            domain = sender_email.split('@')[-1].lower()
            if domain not in sender_name.lower():
                score += 0.4
                reasons.append("Sender name and email domain mismatch")

        # Rule 2: Too many URLs in one email
        if len(data.get('urls', [])) > 3:
            score += 0.3
            reasons.append("Excessive number of URLs in email")

        score = min(score, 1.0)

        return {'score': score, 'reasons': reasons}