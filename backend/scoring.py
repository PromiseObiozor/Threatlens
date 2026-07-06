BEC_CATEGORIES = {"urgency", "secrecy", "financial_request"}
LOW_VALUE_MODEL_TERMS = {"com", "http", "https", "www"}


def _rule_evidence_terms(findings: list[dict], limit: int = 8) -> list[str]:
    """
    Fallback when the ML pipeline cannot expose term contributions safely.
    Uses existing NLP rule evidence so the response still contains useful terms.
    """
    terms = []

    for finding in findings:
        evidence = finding.get("evidence", "")

        for item in evidence.split(","):
            term = item.strip().lower()

            if term and term not in terms:
                terms.append(term)

            if len(terms) >= limit:
                return terms

    return terms


def extract_ml_suspicious_words(
    model,
    text: str,
    nlp_findings: list[dict] | None = None,
    limit: int = 8,
) -> list[str]:
    """
    Returns terms from this email that contributed most strongly toward the
    phishing/spam class in the existing TF-IDF + linear classifier pipeline.

    If the loaded model does not safely expose feature names and coefficients,
    falls back to suspicious terms already found by the NLP rules.
    """
    nlp_findings = nlp_findings or []

    try:
        named_steps = getattr(model, "named_steps", {})
        vectorizer = named_steps.get("tfidf")
        classifier = named_steps.get("classifier")

        if vectorizer is None or classifier is None:
            for _, step in getattr(model, "steps", []):
                if vectorizer is None and hasattr(step, "get_feature_names_out"):
                    vectorizer = step
                if classifier is None and hasattr(step, "coef_"):
                    classifier = step

        if vectorizer is None or classifier is None:
            raise ValueError("Model pipeline does not expose TF-IDF coefficients")

        feature_names = vectorizer.get_feature_names_out()
        coefficients = classifier.coef_

        if coefficients.ndim != 2 or coefficients.shape[1] != len(feature_names):
            raise ValueError("Model coefficients do not match TF-IDF features")

        classes = list(getattr(classifier, "classes_", []))

        if len(classes) == 2 and 1 in classes:
            spam_class_index = classes.index(1)
            phishing_coefficients = (
                coefficients[0]
                if spam_class_index == 1
                else -coefficients[0]
            )
        elif coefficients.shape[0] == 1:
            phishing_coefficients = coefficients[0]
        else:
            raise ValueError("Cannot identify phishing class coefficients")

        vector = vectorizer.transform([text])
        row = vector[0]
        contributions = []

        for feature_index, tfidf_value in zip(row.indices, row.data):
            coefficient = phishing_coefficients[feature_index]
            contribution = tfidf_value * coefficient
            term = feature_names[feature_index].strip().lower()

            if (
                contribution > 0
                and any(char.isalpha() for char in term)
                and term not in LOW_VALUE_MODEL_TERMS
            ):
                contributions.append((contribution, term))

        contributions.sort(reverse=True)

        suspicious_terms = []
        for _, term in contributions:
            if term not in suspicious_terms:
                suspicious_terms.append(term)

            if len(suspicious_terms) >= limit:
                break

        if suspicious_terms:
            return suspicious_terms
    except Exception:
        pass

    return _rule_evidence_terms(nlp_findings, limit=limit)


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
