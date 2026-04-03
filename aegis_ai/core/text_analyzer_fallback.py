def fallback_text_analyze(text: str) -> dict:
    """Enhanced rule-based fallback when ML model fails to load"""
    if not text or not text.strip():
        return {'score': 0.0, 'reasons': []}

    text_lower = text.lower()
    score = 0.0
    reasons = []

    # Urgency language
    urgency = ['immediately', 'urgent', 'suspended', 'verify now', 'account locked',
               'action required', 'within 24 hours', 'expire', 'limited time',
               'act now', 'final warning', 'last chance', 'temporary hold',
               'unauthorized access', 'unusual activity']
    matches = [w for w in urgency if w in text_lower]
    if matches:
        score += min(0.35 + 0.05 * len(matches), 0.5)
        reasons.append(f"Urgency language detected: {', '.join(matches[:3])}")

    # Credential / sensitive info requests
    creds = ['password', 'otp', 'pin', 'login credentials', 'verify your identity',
             'social security', 'credit card', 'bank account', 'routing number',
             'ssn', 'date of birth', 'mother\'s maiden', 'security question',
             'enter your', 'confirm your', 'update your payment']
    matches = [w for w in creds if w in text_lower]
    if matches:
        score += min(0.35 + 0.05 * len(matches), 0.5)
        reasons.append(f"Request for credentials/sensitive info: {', '.join(matches[:3])}")

    # Brand impersonation
    brands = ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
              'netflix', 'facebook', 'instagram', 'wells fargo', 'chase',
              'citibank', 'irs', 'usps', 'fedex', 'ups', 'dhl', 'whatsapp']
    matches = [b for b in brands if b in text_lower]
    if matches:
        score += 0.2
        reasons.append(f"Brand name reference: {', '.join(matches[:3])}")

    # Threatening language
    threats = ['will be closed', 'will be terminated', 'legal action',
               'report to authorities', 'will be fined', 'account will be',
               'permanently', 'deactivated', 'blocked', 'restricted']
    matches = [t for t in threats if t in text_lower]
    if matches:
        score += 0.25
        reasons.append(f"Threatening language: {', '.join(matches[:2])}")

    # Links / call-to-action
    import re
    url_count = len(re.findall(r'https?://\S+', text_lower))
    if url_count > 0:
        score += 0.1
        if url_count > 2:
            score += 0.1
            reasons.append(f"Multiple URLs embedded ({url_count} found)")

    # Click bait patterns
    click_patterns = ['click here', 'click below', 'click the link',
                      'tap here', 'open the attachment', 'download']
    matches = [c for c in click_patterns if c in text_lower]
    if matches:
        score += 0.2
        reasons.append(f"Click-bait pattern: {', '.join(matches[:2])}")

    # Greeting patterns (generic greetings = suspicious)
    generic_greetings = ['dear customer', 'dear user', 'dear account holder',
                         'dear sir', 'dear madam', 'valued customer',
                         'dear member', 'dear client']
    if any(g in text_lower for g in generic_greetings):
        score += 0.15
        reasons.append("Generic greeting (common in phishing)")

    # Grammar / spelling indicators (proxy: excessive exclamation / caps)
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3:
        score += 0.1
        reasons.append("Excessive capitalization detected")

    exclaim_count = text.count('!')
    if exclaim_count > 3:
        score += 0.1
        reasons.append(f"Excessive exclamation marks ({exclaim_count})")

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons
    }