import logging

logger = logging.getLogger('aegis.fusion')


def fuse_scores(text_score: float, url_score: float, rule_score: float, has_urls: bool = True) -> float:
    """
    Intelligent weighted fusion with boosting for high-confidence signals.
    
    Philosophy: If ANY analyzer is very confident, the final score should reflect that.
    A single strong signal (e.g., text_score=0.9) should not be diluted to 0.36.
    """
    logger.info(f"[fusion.py] Inputs → text={text_score}, url={url_score}, rule={rule_score}, has_urls={has_urls}")

    if not has_urls:
        # No URLs present — weight text and rules only
        base_score = (0.55 * text_score) + (0.45 * rule_score)
        logger.info(f"[fusion.py] No URLs → weighted: 0.55*text + 0.45*rule = {base_score:.3f}")
    else:
        # All three signals available
        base_score = (0.40 * text_score) + (0.35 * url_score) + (0.25 * rule_score)
        logger.info(f"[fusion.py] All signals → weighted: 0.40*text + 0.35*url + 0.25*rule = {base_score:.3f}")

    # ── Boost: If any single analyzer is very confident, lift the floor ──
    max_signal = max(text_score, url_score, rule_score)
    
    if max_signal >= 0.8:
        base_score = max(base_score, max_signal * 0.75)
        logger.info(f"[fusion.py] Strong signal boost applied (max={max_signal}) → {base_score:.3f}")
    elif max_signal >= 0.6:
        base_score = max(base_score, max_signal * 0.6)
        logger.info(f"[fusion.py] Moderate signal boost applied (max={max_signal}) → {base_score:.3f}")

    # ── Compound boost: Multiple analyzers agreeing amplifies confidence ──
    high_signals = sum(1 for s in [text_score, url_score, rule_score] if s >= 0.4)
    if high_signals >= 2:
        base_score = min(base_score * 1.15, 1.0)
        logger.info(f"[fusion.py] Compound boost: {high_signals} signals ≥0.4 → {base_score:.3f}")

    final = round(min(base_score, 1.0), 2)
    logger.info(f"[fusion.py] Final fused score: {final}")
    return final