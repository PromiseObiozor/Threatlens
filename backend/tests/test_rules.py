from uuid import uuid4

from fastapi.testclient import TestClient

from main import app
from rules.nlp_rules import analyse_nlp
from rules.url_rules import analyse_urls
from scoring import calculate_final_score, label_from_score


EXPECTED_SCAN_FIELDS = {
    "risk_score",
    "label",
    "ml_score",
    "nlp_score",
    "url_score",
    "metadata_score",
    "reasons",
}

SAFE_EMAIL = {
    "sender": "updates@stripe.com",
    "subject": "Monthly report",
    "body": (
        "Your monthly report is ready. View it here: "
        "https://dashboard.stripe.com/reports/monthly"
    ),
}

PHISHING_EMAIL = {
    "sender": "support@paypa1-secure.com",
    "reply_to": "attacker@gmail.com",
    "subject": "URGENT verify your account",
    "body": (
        "Your account has been compromised. Verify your information "
        "immediately here: http://192.168.4.21/login"
    ),
}

BEC_EMAIL = {
    "sender": "ceo@company-example.com",
    "reply_to": "payments.ceo@gmail.com",
    "subject": "Urgent confidential payment request",
    "body": (
        "I need you to process payment to this vendor today. "
        "Keep this confidential and do not call me. "
        "Please arrange payment before end of day."
    ),
}

REWARD_SCAM_EMAIL = {
    "sender": "rewards@winner-prize.com",
    "reply_to": "claims@gmail.com",
    "subject": "Congratulations, claim your prize",
    "body": (
        "You have been selected for a cash prize. Claim your reward now at "
        "http://reward-prize-claim.com/claim/account"
    ),
}


def unique_credentials() -> dict:
    return {
        "username": f"tester_{uuid4().hex}",
        "password": "StrongPass123!",
    }


def register_and_login(client: TestClient) -> dict[str, str]:
    credentials = unique_credentials()

    register_response = client.post("/register", json=credentials)
    assert register_response.status_code == 200

    login_response = client.post("/login", json=credentials)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def scan(payload: dict) -> dict:
    with TestClient(app) as client:
        headers = register_and_login(client)
        response = client.post("/scan", json=payload, headers=headers)

    assert response.status_code == 200
    return response.json()


def test_register_works():
    credentials = unique_credentials()

    with TestClient(app) as client:
        response = client.post("/register", json=credentials)

    assert response.status_code == 200
    assert response.json() == {"username": credentials["username"]}


def test_login_returns_token():
    credentials = unique_credentials()

    with TestClient(app) as client:
        register_response = client.post("/register", json=credentials)
        login_response = client.post("/login", json=credentials)

    assert register_response.status_code == 200
    assert login_response.status_code == 200

    data = login_response.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]
    assert data["access_token"].count(".") == 2


def test_scan_without_token_is_rejected():
    with TestClient(app) as client:
        response = client.post("/scan", json=SAFE_EMAIL)

    assert response.status_code == 401


def test_scan_with_valid_token_works():
    data = scan(SAFE_EMAIL)

    assert EXPECTED_SCAN_FIELDS.issubset(data.keys())
    assert data["label"] == "Low Risk"


def test_nlp_flags_urgency():
    result = analyse_nlp("Please act urgently within 2 hours")

    assert result["score"] > 0
    assert any("urgency" in finding["id"] for finding in result["findings"])


def test_nlp_flags_bec_pattern_categories():
    result = analyse_nlp(
        "Urgent: process payment today. Keep this confidential and do not call."
    )
    finding_ids = {finding["id"] for finding in result["findings"]}

    assert "nlp_urgency" in finding_ids
    assert "nlp_secrecy" in finding_ids
    assert "nlp_financial_request" in finding_ids


def test_nlp_clean_email():
    result = analyse_nlp("Your monthly report is attached.")

    assert result["score"] == 0
    assert result["findings"] == []


def test_url_flags_ip_and_http_login_path():
    result = analyse_urls("Login at http://192.168.1.1/login")
    reasons = result["findings"][0]["detail"]

    assert result["score"] >= 50
    assert "Raw IP address" in reasons
    assert "insecure HTTP" in reasons
    assert "suspicious action keyword" in reasons


def test_url_flags_suspicious_domain_and_path_words():
    result = analyse_urls("Visit http://reward-prize-claim.com/claim/account")
    reasons = result["findings"][0]["detail"]

    assert result["score"] >= 60
    assert "Excessive hyphens" in reasons
    assert "suspicious phishing keyword" in reasons
    assert "suspicious action keyword" in reasons


def test_url_clean_domain():
    result = analyse_urls("See https://Stripe.com/docs")

    assert result["score"] == 0


def test_calculate_final_score_uses_all_four_layers():
    assert calculate_final_score(
        ml_score=50,
        nlp_score=10,
        url_score=10,
        metadata_score=10,
    ) == 28

    assert label_from_score(75) == "High Risk"
    assert label_from_score(55) == "Medium Risk"
    assert label_from_score(20) == "Low Risk"


def test_calculate_final_score_applies_bec_escalation():
    assert calculate_final_score(
        ml_score=54,
        nlp_score=42,
        url_score=0,
        metadata_score=35,
        nlp_categories={"urgency", "secrecy", "financial_request"},
        reply_to_mismatch=False,
    ) >= 40

    assert calculate_final_score(
        ml_score=54,
        nlp_score=42,
        url_score=0,
        metadata_score=35,
        nlp_categories={"urgency", "secrecy", "financial_request"},
        reply_to_mismatch=True,
    ) >= 70


def test_calculate_final_score_applies_high_ml_floor():
    assert calculate_final_score(
        ml_score=90,
        nlp_score=10,
        url_score=0,
        metadata_score=0,
    ) >= 60


def test_scan_response_includes_all_scores():
    data = scan(PHISHING_EMAIL)

    assert EXPECTED_SCAN_FIELDS.issubset(data.keys())
    assert isinstance(data["reasons"], list)
    assert data["ml_score"] > 0
    assert data["nlp_score"] > 0
    assert data["url_score"] > 0
    assert data["metadata_score"] > 0


def test_scan_safe_email_returns_low_risk():
    data = scan(SAFE_EMAIL)

    assert EXPECTED_SCAN_FIELDS.issubset(data.keys())
    assert data["label"] == "Low Risk"
    assert data["risk_score"] < 40
    assert data["nlp_score"] == 0
    assert data["url_score"] == 0
    assert data["metadata_score"] == 0
    assert data["reasons"] == ["No major suspicious indicators detected"]


def test_scan_obvious_phishing_email_returns_high_risk():
    data = scan(PHISHING_EMAIL)

    assert data["label"] == "High Risk"
    assert data["risk_score"] >= 70
    assert any("ML model detected" in reason for reason in data["reasons"])
    assert any("Credential request" in reason for reason in data["reasons"])
    assert any("Raw IP address" in reason for reason in data["reasons"])
    assert any("imitate paypal" in reason for reason in data["reasons"])


def test_scan_bec_email_does_not_return_low_risk():
    data = scan(BEC_EMAIL)

    assert data["label"] == "High Risk"
    assert data["risk_score"] >= 70
    assert data["url_score"] == 0
    assert any("BEC pattern detected" in reason for reason in data["reasons"])
    assert any("Reply-To domain mismatch" in reason for reason in data["reasons"])


def test_scan_reward_scam_does_not_return_low_risk():
    data = scan(REWARD_SCAM_EMAIL)

    assert data["label"] in {"Medium Risk", "High Risk"}
    assert data["risk_score"] >= 40
    assert any("Reward bait" in reason for reason in data["reasons"])
    assert any("suspicious phishing keyword" in reason for reason in data["reasons"])
