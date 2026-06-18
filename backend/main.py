from pathlib import Path
import joblib
from fastapi import FastAPI, HTTPException

from schemas import EmailScanRequest, EmailScanResponse
from scoring import (
    calculate_final_score,
    has_bec_pattern,
    has_reply_to_mismatch,
    label_from_score,
)
from rules.nlp_rules import analyse_nlp
from rules.url_rules import score_urls
from rules.metadata_rules import score_metadata


app = FastAPI(
    title="Threatlens API",
    description="API for scanning emails for potential phishing threats using ML and heuristic rules.",
    version="1.0.2"
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "ml" / "models" / "threatlens_baseline_model.joblib"

model = None


@app.on_event("startup")
def load_model():
    """
    Loads the trained ML model when the API starts.
    """
    global model

    if not MODEL_PATH.exists():
        raise RuntimeError(f"Model file not found at: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)


@app.get("/")
def root():
    return {
        "message": "ThreatLens API is running",
        "docs": "Go to /docs to test the API"
    }


@app.post("/scan", response_model=EmailScanResponse)
def scan_email(request: EmailScanRequest):
    """
    Scans an email and returns:
    - ML score
    - NLP/rule score
    - URL score
    - Metadata score
    - Final risk score
    - Risk label
    - Reasons
    """
    if model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded")

    combined_text = f"{request.subject} {request.body}"

    try:
        spam_probability = model.predict_proba([combined_text])[0][1]
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Model prediction failed: {str(error)}"
        )

    ml_score = round(spam_probability * 100)

    nlp_result = analyse_nlp(combined_text)
    nlp_score = nlp_result["score"]
    nlp_categories = {
        finding["id"].replace("nlp_", "", 1)
        for finding in nlp_result["findings"]
    }

    url_score, url_reasons, extracted_urls = score_urls(request.body)

    metadata_score, metadata_reasons = score_metadata(
        sender=request.sender,
        reply_to=request.reply_to
    )
    reply_to_mismatch = has_reply_to_mismatch(metadata_reasons)

    final_score = calculate_final_score(
        ml_score=ml_score,
        nlp_score=nlp_score,
        url_score=url_score,
        metadata_score=metadata_score,
        nlp_categories=nlp_categories,
        reply_to_mismatch=reply_to_mismatch
    )

    label = label_from_score(final_score)

    reasons = []

    if ml_score >= 70:
        reasons.append(f"ML model detected suspicious email content with score {ml_score}")

    if ml_score >= 85 and (nlp_score > 0 or url_score > 0 or metadata_score > 0):
        reasons.append("Very high ML score is reinforced by rule-based indicators")

    if has_bec_pattern(nlp_categories):
        reasons.append(
            "BEC pattern detected: urgency, secrecy, and financial request cues appear together"
        )

        if reply_to_mismatch:
            reasons.append(
                "BEC escalation: payment request is combined with a Reply-To domain mismatch"
            )

    for finding in nlp_result["findings"]:
        evidence = finding.get("evidence")
        reason = f"{finding['title']}: {finding['detail']}"

        if evidence:
            reason = f"{reason} Evidence: {evidence}"

        reasons.append(reason)

    reasons.extend(url_reasons)
    reasons.extend(metadata_reasons)

    if not reasons:
        reasons.append("No major suspicious indicators detected")

    return EmailScanResponse(
        risk_score=final_score,
        label=label,
        ml_score=ml_score,
        nlp_score=nlp_score,
        url_score=url_score,
        metadata_score=metadata_score,
        reasons=reasons
    )
