import re 
from typing import List, Dict

#Each sequence = (category, regex pattern, weight, human label)
PATTERNS = [
   (
        "urgency",
        r"\b(urgent|urgently|immediately|asap|within \d+ hours?|within 24 hours|today|before close of business|final warning|last chance)\b", 15,  "Urgency / Pressure",),
    (
        "authority",
        r"\b(ceo|chief executive|director|hr|it support|admin|finance department|accounts department|payroll|manager|security team)\b", 10, "Authority impersonation",),
    (
        "fear",
        r"\b(suspended|terminated|legal action|locked|compromised|blocked|unauthorised access|unauthorized access|unusual activity|security alert)\b", 15, "Fear / threat",),
    (
        "credential",
        r"\b(verify your information|verify your account|confirm your details|update your details|login|log in|password|credentials?|sign in|authentication|security code)\b", 20, "Credential request",),
    (
        "reward",
        r"\b(won|prize|claim your|congratulations|gift card|bonus|reward|selected)\b", 10, "Reward bait",),
    (
        "secrecy",
        r"\b(don't tell|do not tell|confidential|strictly confidential|between us|do not share|keep this private|do not discuss)\b", 12, "Secrecy / request",),
    (
        "financial_request",
        r"\b(invoice|payment|payment portal|arrange payment|process payment|outstanding balance|remittance|wire transfer|transfer funds|bank transfer|sort code|iban|account number|payee|billing)\b", 15, "Financial / payment request",),
    (
        "bank_change",
        r"\b(bank details have changed|new bank details|updated bank details|changed payment details|new payment account|use the new payment|new account number|account details have changed|bank details changed)\b",  20, "Changed bank details",),
]

def analyse_nlp(text: str) -> Dict:
    """
    Analyses email subject/body text for phishing and BEC language cues.
    Returns a score and a list of explainable findings.
    """
    findings: List[Dict] = []
    score = 0
    lower = text.lower()
    for cat, pattern, weight, label in PATTERNS:
        matches = re.findall(pattern, lower)
        if matches: 
            unique_matches = set(matches)
            score += weight

            findings.append({
                "id": f"nlp_{cat}",
                "severity": "high" if weight >= 15 else "medium",
                "title": label,
                "detail": f"Found {len(matches)} match(es) for {cat} cues.",
                "evidence": ", ".join(set(matches))[:200],
            })
    return {
        "score": min(score, 100),
          "findings": findings
          }

#Compatability aliases in case main.py imports a different function name
analyse_nlp = analyse_nlp
run_nlp_rules = analyse_nlp
check_nlp_rules = analyse_nlp
