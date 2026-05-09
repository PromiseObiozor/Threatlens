def combine_scores(nlp_score: int, url_score: int) -> dict:
    final = min(nlp_score + url_score, 100)
    if final >= 75: level = "critical"
    elif final >= 50: level = "high"
    elif final >= 25: level = "medium"
    else:             level = "low"
    return {"final_score": final, "risk_level": level}
