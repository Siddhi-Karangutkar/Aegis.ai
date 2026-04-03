def fallback_text_analyze(text: str) -> dict:
    """Rule-based fallback when ML model fails to load"""
    if not text or not text.strip():
        return {'score': 0.0, 'reasons': []}

    text_lower = text.lower()
    score = 0.0
    reasons = []

    # Urgency
    urgency = ['immediately', 'urgent', 'suspended', 'verify now', 'account locked', 'action required']
    if any(word in text_lower for word in urgency):
        score += 0.35
        reasons.append("Urgency language detected")

    # Credential requests
    creds = ['password', 'otp', 'pin', 'login credentials', 'verify your identity']
    if any(word in text_lower for word in creds):
        score += 0.35
        reasons.append("Request for credentials/OTP detected")

    # Brand impersonation
    if any(b in text_lower for b in ['bank', 'paypal', 'amazon', 'microsoft']):
        score += 0.25
        reasons.append("Brand impersonation detected")

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons
    }