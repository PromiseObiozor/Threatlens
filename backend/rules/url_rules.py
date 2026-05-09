import re
from urllib.parse import urlparse 

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".click", ".zip"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def analyse_urls(body: str) -> dict:
    urls = URL_RE.findall(body)
    findings, url_details = [], []
    score = 0

    for url in urls:
        reasons = []
        host = urlparse(url).hostname or ""

        if IP_RE.match(host):
            reasons.append("Raw IP address instead of domain")
            score += 25

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reasons.append(f"Suspicious TLD ({host.rsplit('.', 1)[-1]})")
            score += 15

        if host.count("-") >= 2:
            reasons.append("Excessive hyphens in domain")
            score += 5

        url_details.append({"url": url, "suspicious": bool(reasons), "reasons": reasons})
        if reasons:
            findings.append({
                "id": f"url_{len(findings)}",
                "severity": "high" if score >= 25 else "medium",
                "title": "Suspicious URL",
                "detail": "; ".join(reasons),
                "evidence": url,
            })
    
    return{"score": min(score, 100), "findings": findings, "urls": url_details}