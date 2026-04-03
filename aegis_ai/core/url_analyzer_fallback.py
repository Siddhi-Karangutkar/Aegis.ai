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
            parsed = urlparse(url if '://' in url else f'http://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            domain = url

        # ── Check for IP address in URL ──
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.45
            all_reasons.append(f"IP address detected in URL: {url[:60]}")

        # ── Excessive subdomains (more than 3 dots) ──
        if domain.count('.') > 3:
            score += 0.3
            all_reasons.append(f"Excessive subdomains in: {domain[:60]}")

        # ── Suspicious length (very long URLs) ──
        if len(url) > 75:
            score += 0.15
            all_reasons.append(f"Suspiciously long URL ({len(url)} chars)")

        # ── Phishing keywords in URL ──
        phishing_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'signin', 'password', 'auth', 'wallet', 'suspend',
            'restore', 'unlock', 'credential', 'validate', 'security',
            'authenticate', 'reactivate', 'recover'
        ]
        matches = [kw for kw in phishing_keywords if kw in url_lower]
        if matches:
            # Scale: 1 keyword = +0.2, 2 = +0.35, 3+ = +0.5
            kw_score = min(0.2 + 0.15 * (len(matches) - 1), 0.5)
            score += kw_score
            all_reasons.append(f"Phishing keywords in URL: {', '.join(matches[:4])}")

        # ── Brand name in URL but NOT official domain ──
        brands = {
            'paypal': 'paypal.com', 'amazon': 'amazon.com',
            'microsoft': 'microsoft.com', 'apple': 'apple.com',
            'google': 'google.com', 'netflix': 'netflix.com',
            'facebook': 'facebook.com', 'instagram': 'instagram.com',
            'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
            'bankofamerica': 'bankofamerica.com'
        }
        for brand, official in brands.items():
            if brand in domain and official not in domain:
                score += 0.4
                all_reasons.append(f"Brand impersonation: '{brand}' in domain but not {official}")
                break

        # ── URL shorteners ──
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy']
        if any(s in url_lower for s in shorteners):
            score += 0.3
            all_reasons.append("URL shortener detected — possible redirect masking")

        # ── Suspicious TLDs ──
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click', '.icu', '.work']
        if any(domain.endswith(tld) or tld + '/' in url_lower for tld in suspicious_tlds):
            score += 0.25
            all_reasons.append("Suspicious top-level domain detected")

        # ── @ symbol in URL ──
        if '@' in url:
            score += 0.4
            all_reasons.append("'@' symbol in URL — possible credential redirect")

        # ── Hyphen-heavy domains ──
        if domain.count('-') >= 2:
            score += 0.25
            all_reasons.append(f"Hyphen-heavy domain: {domain[:60]}")

        # ── Numeric substitutions (e.g., paypai, amaz0n) ──
        leet_patterns = ['0' in domain and any(b in domain for b in ['amaz', 'g0ogle', 'micr']),
                         '1' in domain and any(b in domain for b in ['app1e', 'paypa1']),
                         'rn' in domain]  # rn looks like m
        if any(leet_patterns):
            score += 0.2
            all_reasons.append("Possible character substitution/homoglyph attack")

        if score > max_score:
            max_score = score

    return {
        'score': round(min(max_score, 1.0), 2),
        'reasons': list(set(all_reasons))[:6]
    }
