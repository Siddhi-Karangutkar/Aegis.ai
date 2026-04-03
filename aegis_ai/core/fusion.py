def fuse_scores(text_score: float, url_score: float, rule_score: float, has_urls: bool = True) -> float:
    """
    Weighted fusion with intelligent handling when no URLs are present
    """
    if not has_urls:
        # Reduce URL weight dramatically if no URLs exist
        final_score = (0.6 * text_score) + (0.4 * rule_score)
    else:
        final_score = (0.4 * text_score) + (0.4 * url_score) + (0.2 * rule_score)

    return round(min(final_score, 1.0), 2)