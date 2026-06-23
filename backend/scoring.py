BEC_CATEGORIES = {"urgency", "secrecy", "financial_request"}


def label_from_score(score: int) -> str:
    """
    Converts numeric risk score into a readable risk label.
    """
    if score >= 70:
        return "High Risk"
    if score >= 40:
        return "Medium Risk"
    return "Low Risk"


def has_bec_pattern(nlp_categories: set[str]) -> bool:
    """
    Detects a classic BEC pattern:
    pressure + secrecy + a financial/payment request.
    """
    return BEC_CATEGORIES.issubset(nlp_categories)


def has_reply_to_mismatch(metadata_reasons: list[str]) -> bool:
    """
    Detects whether metadata rules found a Reply-To mismatch.
    """
    return any("Reply-To domain differs" in reason for reason in metadata_reasons)


def count_triggered_layers(
    ml_score: int,
    nlp_score: int,
    url_score: int,
    metadata_score: int
) -> int:
    """
    Counts how many detection layers produced meaningful risk.
    """
    return sum(
        [
            ml_score >= 70,
            nlp_score >= 20,
            url_score >= 20,
            metadata_score >= 35,
        ]
    )


def calculate_final_score(
    ml_score: int,
    nlp_score: int,
    url_score: int,
    metadata_score: int,
    nlp_categories: set[str] | None = None,
    reply_to_mismatch: bool = False
) -> int:
    """
    Combines all component scores into one final 0-100 score, then applies
    calibration floors for high-confidence patterns.

    Base weights:
    - ML model: 45%
    - NLP/rule checks: 20%
    - URL rules: 25%
    - Metadata rules: 10%
    """
    nlp_categories = nlp_categories or set()

    final_score = (
        ml_score * 0.45
        + nlp_score * 0.20
        + url_score * 0.25
        + metadata_score * 0.10
    )

    score = round(final_score)
    triggered_layers = count_triggered_layers(
        ml_score=ml_score,
        nlp_score=nlp_score,
        url_score=url_score,
        metadata_score=metadata_score
    )

    if ml_score >= 85:
        score = max(score, 60)

        if triggered_layers >= 2:
            score = max(score, 70)

    if triggered_layers >= 3:
        score = max(score, 70)
    elif triggered_layers >= 2:
        score = max(score, 50)

    if has_bec_pattern(nlp_categories):
        score = max(score, 45)

        if reply_to_mismatch:
            score = max(score, 70)

    return min(score, 100)
