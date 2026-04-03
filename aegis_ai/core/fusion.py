def fuse_scores(text_score: float, url_score: float, rule_score: float, has_urls: bool = True) -> float:
    """
    Intelligent weighted fusion with boosting for high-confidence signals.
    
    Philosophy: If ANY analyzer is very confident, the final score should reflect that.
    A single strong signal (e.g., text_score=0.9) should not be diluted to 0.36.
    """
    if not has_urls:
        # No URLs present — weight text and rules only
        base_score = (0.55 * text_score) + (0.45 * rule_score)
    else:
        # All three signals available
        base_score = (0.40 * text_score) + (0.35 * url_score) + (0.25 * rule_score)

    # ── Boost: If any single analyzer is very confident, lift the floor ──
    max_signal = max(text_score, url_score, rule_score)
    
    if max_signal >= 0.8:
        # Strong signal — ensure final is at least 70% of the max
        base_score = max(base_score, max_signal * 0.75)
    elif max_signal >= 0.6:
        # Moderate signal — ensure final is at least 55% of the max
        base_score = max(base_score, max_signal * 0.6)

    # ── Compound boost: Multiple analyzers agreeing amplifies confidence ──
    high_signals = sum(1 for s in [text_score, url_score, rule_score] if s >= 0.4)
    if high_signals >= 2:
        base_score = min(base_score * 1.15, 1.0)  # 15% boost for agreement

    return round(min(base_score, 1.0), 2)