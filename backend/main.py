import json
from pathlib import Path

import joblib
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    register_user,
)
from .database import Base, engine, get_db
from .models import ScanHistory, User
from .schemas import (
    EmailScanRequest,
    EmailScanResponse,
    ScanHistoryResponse,
    TokenResponse,
    UserCredentials,
    UserResponse,
)
from .scoring import (
    calculate_final_score,
    extract_ml_suspicious_words,
    has_bec_pattern,
    has_reply_to_mismatch,
    label_from_score,
)
from .rules.metadata_rules import score_metadata
from .rules.nlp_rules import analyse_nlp
from .rules.url_rules import score_urls


app = FastAPI(
    title="Threatlens API",
    description="API for scanning emails for potential phishing threats using ML and heuristic rules.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "ml" / "models" / "threatlens_baseline_model.joblib"

model = None


@app.on_event("startup")
def startup_event():
    """
    Creates database tables and loads the trained ML model.
    """
    global model

    Base.metadata.create_all(bind=engine)

    if not MODEL_PATH.exists():
        raise RuntimeError(f"Model file not found at: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)


@app.get("/")
def root():
    return {
        "message": "ThreatLens API is running",
        "docs": "Go to /docs to test the API",
    }


@app.post("/register", response_model=UserResponse)
def register(
    credentials: UserCredentials,
    db: Session = Depends(get_db),
):
    """
    Registers a user and stores the account in SQLite.
    """
    try:
        return register_user(
            db=db,
            username=credentials.username,
            password=credentials.password,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/login", response_model=TokenResponse)
def login(
    credentials: UserCredentials,
    db: Session = Depends(get_db),
):
    """
    Authenticates a user and returns a JWT bearer token.
    """
    user = authenticate_user(
        db=db,
        username=credentials.username,
        password=credentials.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(access_token=create_access_token(user["username"]))


@app.post("/scan", response_model=EmailScanResponse)
def scan_email(
    request: EmailScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Scans an email and returns:
    - ML score
    - NLP/rule score
    - URL score
    - Metadata score
    - Final risk score
    - Risk label
    - Reasons
    - ML terms and reasons grouped by detection layer

    The result is also saved to the logged-in user's scan history.
    """
    if model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded")

    combined_text = f"{request.subject} {request.body}"

    try:
        spam_probability = model.predict_proba([combined_text])[0][1]
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Model prediction failed: {str(error)}",
        ) from error

    ml_score = round(spam_probability * 100)

    nlp_result = analyse_nlp(combined_text)
    nlp_score = nlp_result["score"]
    ml_suspicious_words = (
        extract_ml_suspicious_words(
            model=model,
            text=combined_text,
            nlp_findings=nlp_result["findings"],
        )
        if ml_score >= 70
        else []
    )

    nlp_categories = {
        finding["id"].replace("nlp_", "", 1)
        for finding in nlp_result["findings"]
    }

    url_score, url_reasons, _extracted_urls = score_urls(request.body)

    metadata_score, metadata_reasons = score_metadata(
        sender=request.sender,
        reply_to=request.reply_to,
    )
    reply_to_mismatch = has_reply_to_mismatch(metadata_reasons)

    final_score = calculate_final_score(
        ml_score=ml_score,
        nlp_score=nlp_score,
        url_score=url_score,
        metadata_score=metadata_score,
        nlp_categories=nlp_categories,
        reply_to_mismatch=reply_to_mismatch,
    )

    label = label_from_score(final_score)

    ml_reasons = []
    nlp_reasons = []

    if ml_score >= 70:
        ml_reasons.append(
            f"ML model detected suspicious email content with score {ml_score}"
        )

    if ml_score >= 85 and (nlp_score > 0 or url_score > 0 or metadata_score > 0):
        ml_reasons.append(
            "Very high ML score is reinforced by rule-based indicators"
        )

    if has_bec_pattern(nlp_categories):
        nlp_reasons.append(
            "BEC pattern detected: urgency, secrecy, and financial request cues appear together"
        )

        if reply_to_mismatch:
            nlp_reasons.append(
                "BEC escalation: payment request is combined with a Reply-To domain mismatch"
            )

    for finding in nlp_result["findings"]:
        evidence = finding.get("evidence")
        reason = f"{finding['title']}: {finding['detail']}"

        if evidence:
            reason = f"{reason} Evidence: {evidence}"

        nlp_reasons.append(reason)

    reasons = [
        *ml_reasons,
        *nlp_reasons,
        *url_reasons,
        *metadata_reasons,
    ]

    if not reasons:
        reasons.append("No major suspicious indicators detected")

    scan_result = EmailScanResponse(
        risk_score=final_score,
        label=label,
        ml_score=ml_score,
        nlp_score=nlp_score,
        url_score=url_score,
        metadata_score=metadata_score,
        reasons=reasons,
        ml_suspicious_words=ml_suspicious_words,
        explanation={
            "ml": ml_reasons,
            "nlp": nlp_reasons,
            "url": url_reasons,
            "metadata": metadata_reasons,
        },
    )

    saved_scan = ScanHistory(
        user_id=current_user.id,
        subject=request.subject,
        sender=request.sender,
        reply_to=request.reply_to,
        body_preview=request.body[:300],
        risk_score=scan_result.risk_score,
        label=scan_result.label,
        ml_score=scan_result.ml_score,
        nlp_score=scan_result.nlp_score,
        url_score=scan_result.url_score,
        metadata_score=scan_result.metadata_score,
        reasons=json.dumps(scan_result.reasons),
    )

    db.add(saved_scan)
    db.commit()

    return scan_result


@app.get("/history", response_model=list[ScanHistoryResponse])
def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns the logged-in user's scans, newest first.
    """
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )

    return [
        ScanHistoryResponse(
            id=scan.id,
            subject=scan.subject,
            sender=scan.sender,
            reply_to=scan.reply_to,
            body_preview=scan.body_preview,
            risk_score=scan.risk_score,
            label=scan.label,
            ml_score=scan.ml_score,
            nlp_score=scan.nlp_score,
            url_score=scan.url_score,
            metadata_score=scan.metadata_score,
            reasons=json.loads(scan.reasons or "[]"),
            created_at=scan.created_at,
        )
        for scan in scans
    ]


@app.delete("/history/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan_history_item(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Deletes one saved scan belonging to the logged-in user.
    """
    scan = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.id == scan_id,
            ScanHistory.user_id == current_user.id,
        )
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan history item not found",
        )

    db.delete(scan)
    db.commit()

    return None
