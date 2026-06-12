def label_from_score(score: int) -> str:
    """
    Converts numeric risk score into a readable risk label.
    """
    if score >= 70:
        return "High Risk"
    if score >= 40:
        return "Medium Risk"
    return "Low Risk"


def calculate_final_score(
    ml_score: int,
    url_score: int,
    metadata_score: int
) -> int:
    """
    Combines all component scores into one final 0-100 score.

    Current weights:
    - ML model: 50%
    - URL rules: 30%
    - Metadata rules: 20%
    """
    final_score = (
        ml_score * 0.50
        + url_score * 0.30
        + metadata_score * 0.20
    )

    return round(final_score)