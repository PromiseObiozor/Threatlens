Threatlens

Threatlens is a small email threat scanner. It lets a user paste or load an email, scan it, and receive a risk score with a breakdown of suspicious language and suspicious URLs.

The app has two parts:

- `backend/`: FastAPI API that analyses email text and URLs.
- `frontend/`: React/Vite interface for loading sample emails and viewing scan results.

## Features

- Scan an email sender, subject, and body.
- Detect phishing-style NLP cues such as urgency, fear, authority impersonation, secrecy, rewards, and credential requests.
- Detect suspicious URLs such as raw IP addresses, suspicious top-level domains, and domains with many hyphens.
- Return a final risk score from `0` to `100`.
- Show separate NLP and URL findings in the frontend.
- Include clean and malicious sample emails for quick testing.

## Project Structure

```text
threatlens/
├── backend/
│   ├── main.py              # FastAPI app and scan endpoint
│   ├── schemas.py           # Request and finding models
│   ├── scoring.py           # Combines NLP and URL scores
│   ├── rules/
│   │   ├── nlp_rules.py     # Text-based phishing rules
│   │   └── url_rules.py     # URL-based phishing rules
│   └── tests/
│       └── test_rules.py    # Backend rule tests
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Main React UI
│   │   ├── api.js           # Axios API client
│   │   └── App.css          # App styling
│   └── package.json
└── pytest.ini
