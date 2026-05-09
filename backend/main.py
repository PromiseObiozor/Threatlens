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