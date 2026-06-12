import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
SUSPICIOUS_TLDS = {
    ".zip", ".xyz", ".top", ".click", ".link", ".work", ".country", ".stream"
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}


def extract_urls(text: str) -> list[str]:
    """
    Finds URLs inside email text.
    """
    if not text:
        return []

    return URL_PATTERN.findall(text)


def has_ip_address(url: str) -> bool:
    """
    Checks if a URL contains an IP address instead of a normal domain.
    Example: http://192.168.1.1/login
    """
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return bool(ip_pattern.search(url))


def get_domain(url: str) -> str:
    """
    Extracts the domain from a URL.
    """
    if url.startswith("www."):
        url = "http://" + url

    parsed = urlparse(url)
    return parsed.netloc.lower()


def score_urls(text: str) -> tuple[int, list[str], list[str]]:
    """
    Scores suspicious URL behaviour from 0 to 100.
    Returns:
    - url score
    - reasons
    - extracted URLs
    """
    urls = extract_urls(text)
    reasons = []
    score = 0

    if not urls:
        return 0, reasons, urls

    for url in urls:
        domain = get_domain(url)

        if has_ip_address(url):
            score += 35
            reasons.append(f"URL contains an IP address: {url}")

        if len(url) > 100:
            score += 20
            reasons.append(f"URL is unusually long: {url}")

        if "@" in url:
            score += 25
            reasons.append(f"URL contains '@' symbol: {url}")

        if domain.count("-") >= 3:
            score += 15
            reasons.append(f"Domain contains excessive hyphens: {domain}")

        if domain.count(".") >= 4:
            score += 15
            reasons.append(f"URL contains many subdomains: {domain}")

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 20
            reasons.append(f"URL uses suspicious top-level domain: {domain}")

        if domain in URL_SHORTENERS:
            score += 20
            reasons.append(f"URL uses a known shortener: {domain}")

    return min(score, 100), reasons, urls


"""
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
"""