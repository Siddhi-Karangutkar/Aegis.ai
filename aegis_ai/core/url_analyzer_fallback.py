import re
from urllib.parse import urlparse


def fallback_url_analyze(urls: list) -> dict:
    """Rule-based URL analysis fallback when ML model fails to load."""
    if not urls:
        return {'score': 0.0, 'reasons': []}

    max_score = 0.0
    all_reasons = []

    for url in urls:
        score = 0.0
        url_lower = url.lower()

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
        except Exception:
            domain = url

        # Check for IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.4
            all_reasons.append(f"IP address detected in URL: {url[:60]}")

        # Excessive subdomains (more than 3 dots)
        if domain.count('.') > 3:
            score += 0.3
            all_reasons.append(f"Excessive subdomains in: {domain[:60]}")

        # Suspicious length (very long URLs are often phishing)
        if len(url) > 75:
            score += 0.15
            all_reasons.append(f"Suspiciously long URL ({len(url)} chars)")

        # Known phishing keywords in URL
        phishing_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'signin', 'password', 'auth', 'wallet', 'suspend'
        ]
        matches = [kw for kw in phishing_keywords if kw in url_lower]
        if matches:
            score += 0.2 * min(len(matches), 3)
            all_reasons.append(f"Phishing keywords found in URL: {', '.join(matches[:3])}")

        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        if any(s in url_lower for s in shorteners):
            score += 0.25
            all_reasons.append("URL shortener detected — possible redirect masking")

        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click']
        if any(url_lower.endswith(tld) or tld + '/' in url_lower for tld in suspicious_tlds):
            score += 0.2
            all_reasons.append("Suspicious top-level domain detected")

        # @ symbol in URL (credential phishing trick)
        if '@' in url:
            score += 0.35
            all_reasons.append("'@' symbol in URL — possible credential redirect")

        # Hyphen-heavy domains (e.g. paypal-secure-login-verify.com)
        if domain.count('-') >= 3:
            score += 0.25
            all_reasons.append(f"Hyphen-heavy domain detected: {domain[:60]}")

        if score > max_score:
            max_score = score

    return {
        'score': round(min(max_score, 1.0), 2),
        'reasons': list(set(all_reasons))[:6]
    }
