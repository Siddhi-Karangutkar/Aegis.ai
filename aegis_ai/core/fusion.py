def fuse_scores(text_score: float, url_score: float, rule_score: float) -> float:
    """Weighted fusion as per blueprint"""
    final_score = (0.4 * text_score) + (0.4 * url_score) + (0.2 * rule_score)
    return round(min(final_score, 1.0), 2)