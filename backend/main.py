from pathlib import Path
import joblib
from fastapi import FastAPI, HTTPException
from schemas import EmailScanRequest, EmailScanResponse
from scoring import calculate_final_score, label_from_score
from rules.url_rules import score_urls
from rules.metadata_rules import score_metadata


app = FastAPI(
    title="Threatlens API",
    description="API for scanning emails for potential phishing threats using ML and heuristic rules.",
    version="1.0.1"
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

    final_score = calculate_final_score(
        ml_score=ml_score,
        url_score=url_score,
        metadata_score=metadata_score
    )

    label = label_from_score(final_score)

    reasons = []

    if ml_score >= 70:
        reasons.append(f"ML model detected suspicious email content with score {ml_score}")

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

"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from uuid import uuid4
from datetime import datetime

from schemas import ScanRequest
from rules.nlp_rules import analyse_nlp
from rules.url_rules import analyse_urls
from scoring import combine_scores

app = FastAPI(title = "Threatlens API")

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["http://localhost:5173"],              #react dev server 
    allow_methods = ["*"],
    allow_headers = ["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/scan")
def scan(req: ScanRequest):
    full_text = f"{req.subject}\n{req.body}"
    nlp = analyse_nlp(full_text)
    url = analyse_urls(req.body)
    combined = combine_scores(nlp["score"], url["score"])

    return {
        "id": str(uuid4()),
        "created_at": datetime.utcnow().isoformat(),
        ** combined,
        "nlp": nlp,
        "url": url,
        "urls": url["urls"],
    }
"""