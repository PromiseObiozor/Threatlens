# ThreatLens

ThreatLens is an explainable email threat-detection application developed as a
final-year cybersecurity project. A React/Vite console sends an email to a
FastAPI service, which combines a trained content model with language, URL, and
metadata rules. The result includes an overall risk score, the four component
scores, and readable detection reasons.

## Current features

- Register, log in, log out, and protect scan/history endpoints with JWT bearer
  authentication.
- Enter sender, optional Reply-To, subject, and body fields manually.
- Parse standard raw email source and supported Gmail-style copied text into
  editable fields.
- Load clean, suspicious, and malicious examples for demonstration.
- Analyse email content with four real detection layers:
  - Machine-learning content model: 45% base weight.
  - NLP/social-engineering rules: 20% base weight.
  - URL heuristics: 25% base weight.
  - Sender/Reply-To metadata rules: 10% base weight.
- Show Low Risk (0–39), Medium Risk (40–69), and High Risk (70–100) results.
- Return grouped explanation strings and influential model terms when
  available.
- Save authenticated scan history in SQLite, reload a stored result, and delete
  a scan after confirmation.
- Provide responsive SOC-console, authentication, and methodology views.

The weighted base score is followed by the existing calibration rules for very
high ML scores, agreement between several layers, and business-email-compromise
patterns. For that reason, the final score is not always just the weighted
average.

## Project structure

```text
threatlens/
├── backend/
│   ├── main.py              # FastAPI routes and scan orchestration
│   ├── auth.py              # Password hashing and JWT handling
│   ├── database.py          # SQLAlchemy/SQLite configuration
│   ├── models.py            # User and scan-history tables
│   ├── schemas.py           # API request and response models
│   ├── scoring.py           # Score fusion and ML term extraction
│   ├── rules/               # NLP, URL, and metadata checks
│   └── tests/
├── frontend/
│   ├── src/components/      # Straightforward console UI components
│   ├── src/App.jsx          # Authentication and console state
│   ├── src/api.js           # Axios API client
│   ├── src/emailParser.js   # Raw/Gmail-style email parser
│   └── src/reportUtils.js   # Display helpers and real counters
└── ml/
    ├── models/              # Trained scikit-learn model
    └── scripts/             # Training and dataset inspection
```

## Run locally

Create and activate a Python environment, install
`backend/requirements.txt`, then start the API from the repository root:

```bash
.venv/bin/uvicorn backend.main:app --reload
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend API client defaults to `http://localhost:8000`. Set
`VITE_API_BASE_URL` when the API runs elsewhere. Set a strong
`THREATLENS_JWT_SECRET` outside local development so signed-in sessions remain
valid across backend restarts. Without it, the backend creates a secure temporary
secret when it starts. The SQLite database defaults to `threatlens.db` in the
project root and can be changed with `THREATLENS_DATABASE_URL`.

## Tests

```bash
cd frontend
npm test
npm run lint
npm run build
```

```bash
.venv/bin/python -m pytest
```

## Important limitations

- ThreatLens can produce false positives and false negatives; it supports
  human review rather than replacing it.
- The baseline model uses the project’s Enron spam dataset and does not cover
  every modern attack.
- URL checks analyse text patterns without visiting the destination.
- The application does not currently analyse attachments, query threat
  intelligence, or validate SPF, DKIM, or DMARC.
- History stores only a body preview and flat reason strings, so a historical
  result cannot recreate fresh-scan-only model terms or grouped explanations.

Browser-extension scanning remains possible future work.
