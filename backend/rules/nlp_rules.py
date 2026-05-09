import re 
from typing import List, Dict

#Each sequence = (category, regex pattern, weight, human label)
PATTERNS = [
    ("urgency", r"\b(urgent|urgently|immediately|asap|within \d+ hours?)\b", 15, "Urgency / Pressure"),
    ("authority", r"\b(ceo|director|hr|it support|admin)\b",                 10, "Authority impersonation"),
    ("fear", r"\b(suspended|terminated|legal action|locked|compromised)\b",  15, "Fear / threat"),
    ("credential", r"\b(verify your information|verify your account|login|password|credentials?)\b", 20, "Credential request"),
    ("reward", r"\b(won|prize|claim your|congratulations)\b",                10, "Reward bait"),
    ("secrecy", r"\b(don't tell|confidential|between us)\b",                 12, "Secrecy / request"),
]

def analyse_nlp(text: str) -> Dict:
    findings: List[Dict] = []
    score = 0
    lower = text.lower()
    for cat, pattern, weight, label in PATTERNS:
        matches = re.findall(pattern, lower)
        if matches: 
            score += weight
            findings.append({
                "id": f"nlp_{cat}",
                "severity": "high" if weight >= 15 else "medium",
                "title": label,
                "detail": f"Found {len(matches)} match(es) for {cat} cues.",
                "evidence": ", ".join(set(matches))[:200],
            })
    return {"score": min(score, 100), "findings": findings}
