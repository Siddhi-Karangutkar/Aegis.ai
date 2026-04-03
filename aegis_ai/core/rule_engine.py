import re
import logging

logger = logging.getLogger('aegis.rules')


class RuleEngine:
    """
    Deterministic rule-based analysis that catches patterns
    ML models and text heuristics might miss.
    """
    FREE_EMAIL_DOMAINS = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'protonmail.com', 'icloud.com', 'aol.com', 'yandex.com'
    }

    def analyze(self, data: dict) -> dict:
        logger.info("[rule_engine.py] Running deterministic rule analysis")
        score = 0.0
        reasons = []
        
        email_text = data.get('email_text', '').lower()
        sender_email = data.get('sender_email', '').lower()
        sender_name = data.get('sender_name', '').lower()
        urls = data.get('urls', [])

        # ─── Rule 1: Sender domain mismatch ────────────────────
        if sender_email and '@' in sender_email:
            domain = sender_email.split('@')[-1]
            if domain in self.FREE_EMAIL_DOMAINS and any(
                word in sender_name for word in 
                ['bank', 'support', 'security', 'admin', 'paypal', 'amazon', 'microsoft']
            ):
                score += 0.4
                reasons.append("Company name used with free email domain")
                logger.info(f"[rule_engine.py] Rule 1 fired: sender domain mismatch (+0.4)")

        # ─── Rule 2: Excessive URLs ────────────────────────────
        if len(urls) > 3:
            score += 0.25
            reasons.append(f"Excessive URLs in content ({len(urls)} found)")
            logger.info(f"[rule_engine.py] Rule 2 fired: excessive URLs ({len(urls)}) (+0.25)")

        # ─── Rule 3: Mixed urgency + credential request ───────
        urgency_words = ['immediately', 'urgent', 'suspended', 'locked', 
                         'expire', 'within 24', 'verify now', 'action required']
        cred_words = ['password', 'otp', 'pin', 'login', 'credentials',
                      'verify your', 'confirm your', 'ssn', 'credit card']
        has_urgency = any(w in email_text for w in urgency_words)
        has_creds = any(w in email_text for w in cred_words)
        
        if has_urgency and has_creds:
            score += 0.45
            reasons.append("Urgency combined with credential request — strong phishing signal")
            logger.info("[rule_engine.py] Rule 3 fired: urgency + credentials combo (+0.45)")
        elif has_urgency:
            score += 0.15
        elif has_creds:
            score += 0.15

        # ─── Rule 4: Suspicious link text patterns ─────────────
        # Links that don't match their anchor text (common phishing trick)
        mismatched_link_patterns = [
            r'click\s+here', r'verify\s+now', r'confirm\s+identity',
            r'update\s+account', r'secure\s+your', r'log\s*in\s+now'
        ]
        link_matches = [p for p in mismatched_link_patterns if re.search(p, email_text)]
        if link_matches and len(urls) > 0:
            score += 0.2
            reasons.append("Suspicious call-to-action with embedded links")

        # ─── Rule 5: Impersonation of known services ──────────
        brand_patterns = {
            'paypal': r'paypal(?!\.com/)',
            'amazon': r'amazon(?!\.com/)',
            'microsoft': r'microsoft(?!\.com/)',
            'apple': r'apple(?!\.com/)',
            'netflix': r'netflix(?!\.com/)',
        }
        for brand, pattern in brand_patterns.items():
            if re.search(pattern, email_text):
                # Check if the URL domains DON'T match the brand
                brand_in_url = any(brand in url.lower() for url in urls)
                if brand_in_url:
                    # Brand mentioned in text AND URL contains brand name 
                    # but URL is not the real domain — suspicious
                    official_domains = [f'{brand}.com']
                    is_official = any(
                        any(od in url.lower() for od in official_domains) 
                        for url in urls
                    )
                    if not is_official and urls:
                        score += 0.3
                        reasons.append(f"Possible {brand.title()} impersonation — URL doesn't match official domain")

        # ─── Rule 6: Embedded email addresses in body ──────────
        embedded_emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', email_text)
        if len(embedded_emails) > 1:
            score += 0.1
            reasons.append("Multiple email addresses embedded in content")

        final_score = round(min(score, 1.0), 2)
        logger.info(f"[rule_engine.py] Rules complete → score={final_score}, {len(reasons)} reason(s) fired")
        return {
            'score': final_score,
            'reasons': reasons
        }