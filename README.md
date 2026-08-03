# ThreatLens

ThreatLens is my final-year cybersecurity project. I built it to explore a
simple problem: email scanners often give a warning without clearly showing
the user what caused it. ThreatLens checks an email across four detection
layers and turns the result into a readable risk report.

The project is a local full-stack prototype. The React interface sends email
details to a FastAPI backend, which combines a trained machine-learning model
with language, URL and sender checks. Users can then review the result and
return to previous scans saved in their own history.

## Quick start for an examiner

The easiest way to run the complete project is with Docker Desktop. Docker
Compose is included, so no API keys or separate dataset download are needed.

```bash
git clone https://github.com/PromiseObiozor/Threatlens.git
cd Threatlens
docker compose up --build
```

When both services have started, open:

- ThreatLens: <http://localhost:4173>
- API status: <http://localhost:8000>
- Interactive API documentation: <http://localhost:8000/docs>

On the first visit, create an account with any username of at least three
characters and a password of at least eight characters. There are no fixed
demo credentials. After signing in, the quickest way to test the system is to
load the clean, suspicious and malicious sample emails included in the input
panel. Raw email source or supported Gmail-style copied text can also be pasted
into the parser and corrected before scanning.

Press `Ctrl+C` in the terminal to stop the services. If they were started in
the background, run:

```bash
docker compose down
```

Scan history is stored in a named Docker volume, so it remains available after
a normal restart.

## What the project does

- Registers and authenticates users with JWT bearer tokens.
- Accepts sender, optional Reply-To, subject and body fields.
- Parses standard raw email source and supported Gmail-style copied text.
- Scores email content with a trained scikit-learn spam classifier.
- Detects social-engineering language such as urgency, secrecy, credential
  requests and financial requests.
- Checks URLs for risky patterns without opening or visiting them.
- Compares sender and Reply-To addresses for suspicious mismatches.
- Produces a Low, Medium or High Risk result with a 0–100 score.
- Explains which detection layers affected the result.
- Saves scan history per user in SQLite and allows saved scans to be reviewed
  or deleted.

## How the scoring works

ThreatLens uses four base scores:

- Machine-learning content model: 45%
- NLP and social-engineering rules: 20%
- URL heuristics: 25%
- Sender and Reply-To metadata rules: 10%

The base score is followed by calibration rules for very high model scores,
agreement between several layers and business email compromise patterns. This
means the final result is not always a simple weighted average.

The final labels are:

- Low Risk: 0–39
- Medium Risk: 40–69
- High Risk: 70–100

## Project structure

```text
Threatlens/
├── backend/
│   ├── main.py              # FastAPI routes and scan workflow
│   ├── auth.py              # Password hashing and JWT handling
│   ├── database.py          # SQLite and SQLAlchemy setup
│   ├── scoring.py           # Score combination and model terms
│   ├── rules/               # NLP, URL and metadata checks
│   └── tests/               # Backend tests
├── frontend/
│   ├── src/components/      # Main interface components
│   ├── src/App.jsx          # Authentication and application state
│   ├── src/emailParser.js   # Raw and Gmail-style email parser
│   └── src/reportUtils.js   # Report and history helpers
├── ml/
│   ├── data/                # Enron spam dataset used by the project
│   ├── models/              # Trained model and evaluation image
│   └── scripts/             # Dataset inspection and model training
├── docker-compose.yml
└── README.md
```

## Run without Docker

For local development, use Python 3.12 and Node.js 22.

Start the backend from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload
```

In a second terminal, start the frontend:

```bash
cd frontend
npm ci
npm run dev
```

The development interface runs at <http://localhost:5173>. The frontend uses
`http://localhost:8000` for the API by default. This can be changed with
`VITE_API_BASE_URL`.

For shared or deployed environments, set a strong `THREATLENS_JWT_SECRET`.
Without one, the backend creates a temporary secret when it starts. The SQLite
location can be changed with `THREATLENS_DATABASE_URL`; otherwise it uses
`threatlens.db` in the project root.

## Tests and checks

Run the backend tests from the repository root:

```bash
python -m pytest -q
```

Run the frontend tests and build checks:

```bash
cd frontend
npm test
npm run lint
npm run build
```

## Current limitations

ThreatLens is an academic prototype and should support human review rather
than replace it. It can produce false positives and false negatives.

- The content model is based on the project’s Enron spam dataset and will not
  represent every modern attack.
- URL analysis checks the text of a link but does not visit its destination or
  query a live threat-intelligence service.
- The project does not inspect attachments or validate SPF, DKIM or DMARC.
- Saved history keeps a body preview and flat findings, so it cannot fully
  recreate every detail from a fresh scan.
- The application is designed to run locally and is not presented as a
  production email-security service.

Browser-extension and mailbox integrations are possible future improvements,
but they are not part of the current implementation.
