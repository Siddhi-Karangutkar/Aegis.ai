def fuse_scores(text_score: float, url_score: float, rule_score: float, has_urls: bool = True) -> float:
    """
    Intelligent weighted fusion that adapts to available signals.
    
    Key insight: When only ONE input type is provided (e.g., URL-only scan),
    the absent analyzers should NOT dilute the score. We detect the "mode"
    and weight accordingly.
    """
    has_text = text_score > 0
    has_url_signal = url_score > 0
    has_rules = rule_score > 0

    # ── Determine scan mode and apply appropriate weights ──
    
    if has_text and has_url_signal and has_rules:
        # Full analysis — all signals active
        base_score = (0.40 * text_score) + (0.35 * url_score) + (0.25 * rule_score)
    
    elif has_text and has_url_signal:
        # Text + URL, no rules
        base_score = (0.45 * text_score) + (0.55 * url_score)
    
    elif has_url_signal and has_rules:
        # URL + Rules, no text
        base_score = (0.60 * url_score) + (0.40 * rule_score)
    
    elif has_text and has_rules:
        # Text + Rules, no URLs
        base_score = (0.55 * text_score) + (0.45 * rule_score)
    
    elif has_url_signal:
        # URL-only scan — trust the URL analyzer directly
        base_score = url_score
    
    elif has_text:
        # Text-only scan — trust the text analyzer directly
        base_score = text_score
    
    elif has_rules:
        # Rules only
        base_score = rule_score
    
    else:
        return 0.0

    # ── Boost: Multiple analyzers agreeing amplifies confidence ──
    active_signals = [s for s in [text_score, url_score, rule_score] if s >= 0.3]
    if len(active_signals) >= 2:
        base_score = min(base_score * 1.15, 1.0)  # 15% agreement boost
    if len(active_signals) >= 3:
        base_score = min(base_score * 1.10, 1.0)  # Additional 10% for triple agreement

    return round(min(base_score, 1.0), 2)