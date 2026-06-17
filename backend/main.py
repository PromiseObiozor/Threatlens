from pathlib import Path
import joblib
from fastapi import FastAPI, HTTPException

from schemas import EmailScanRequest, EmailScanResponse
from scoring import calculate_final_score, label_from_score
from rules.url_rules import score_urls
from rules.metadata_rules import score_metadata, is_trusted_sender_domain


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

    url_score, url_reasons, extracted_urls = score_urls(request.body)

    metadata_score, metadata_reasons = score_metadata(
        sender=request.sender,
        reply_to=request.reply_to
    )

    trusted_sender = is_trusted_sender_domain(request.sender)

    final_score = calculate_final_score(
        ml_score=ml_score,
        url_score=url_score,
        metadata_score=metadata_score
    )

    """
    Calibration rule:
    If the ML model is suspicious but URL and metadata checks find nothing,
    and the sender is from a known trusted domain, reduce the final score.
    This prevents false positives like billing@stripe.com being treated as a real threat.
    """
    if trusted_sender and url_score == 0 and metadata_score == 0:
        final_score = min(final_score, 25)

    label = label_from_score(final_score)

    reasons = []

    if ml_score >= 70 and not (trusted_sender and url_score == 0 and metadata_score == 0):
        reasons.append(f"ML model detected suspicious email content with score {ml_score}")

    if ml_score >= 70 and trusted_sender and url_score == 0 and metadata_score == 0:
        reasons.append(
            "ML model score was elevated, but trusted sender metadata and URL checks did not confirm a threat"
        )

    reasons.extend(url_reasons)
    reasons.extend(metadata_reasons)

    if not reasons:
        reasons.append("No major suspicious indicators detected")

    return EmailScanResponse(
        risk_score=final_score,
        label=label,
        ml_score=ml_score,
        url_score=url_score,
        metadata_score=metadata_score,
        reasons=reasons
    )