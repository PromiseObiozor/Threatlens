from rules.nlp_rules import analyse_nlp
from rules.url_rules import analyse_urls
from scoring import combine_scores

def test_nlp_flags_urgency():
    r = analyse_nlp("Please act urgently within 2 hours")
    assert r["score"] > 0
    assert any("urgency" in f["id"] for f in r["findings"])

def test_nlp_clean_email():
    r = analyse_nlp("Your monthly report is attahced.")
    assert r["score"] == 0

def test_url_flags_ip():
    r = analyse_urls("Login at http://192.168.1.1/login")
    assert r["score"] >= 25

def test_url_flags_xyz_tld():
    r = analyse_urls("Visit https://paypal-verify.xyz now")
    assert r["score"] >= 15

def test_url_clean_domain():
    r = analyse_urls("See https://Stripe.com/docs")
    assert r["score"] == 0

def test_malicious_sample_scores_critical():
    subject = "URGENT verify"
    body = "Your account has been compromised. Verify your information here: http://192.168.4.21/login"
    nlp = analyse_nlp(f"{subject}\n{body}")
    url = analyse_urls(body)
    assert combine_scores(nlp["score"], url["score"]) == {
        "final_score": 75,
        "risk_level": "critical",
    }
