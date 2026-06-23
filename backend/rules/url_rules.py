import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)

TRAILING_PUNCTUATION = ".,;:!?)]}'\""

SUSPICIOUS_TLDS = {
    ".zip",
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".country",
    ".stream",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}

SUSPICIOUS_DOMAIN_WORDS = {
    "account",
    "claim",
    "login",
    "prize",
    "reward",
    "secure",
    "verify",
}

SUSPICIOUS_PATH_WORDS = {
    "account",
    "claim",
    "login",
    "reset",
    "secure",
    "update",
    "verify",
}


def extract_urls(text: str) -> list[str]:
    """
    Finds URLs inside email text and removes punctuation captured at the end.
    Example:
    http://example.com/login. becomes http://example.com/login
    """

    if not text:
        return []

    raw_urls = URL_PATTERN.findall(text)
    cleaned_urls = []

    for url in raw_urls:
        cleaned_urls.append(url.rstrip(TRAILING_PUNCTUATION))

    return cleaned_urls


def parse_url(url: str):
    """
    Parses URLs consistently, including links that start with www.
    """
    if url.startswith("www."):
        url = "http://" + url

    return urlparse(url)


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
    parsed = parse_url(url)
    return parsed.netloc.lower()


def _build_finding(index: int, severity: str, detail: str, evidence: str) -> dict:
    return {
        "id": f"url_{index}",
        "severity": severity,
        "title": "Suspicious URL",
        "detail": detail,
        "evidence": evidence,
    }


def analyse_urls(text: str) -> dict:
    """
    Scores suspicious URL behaviour and returns the dictionary format used by /scan.

    Returns:
    {
        "score": int,
        "findings": list,
        "urls": list
    }
    """

    urls = extract_urls(text)
    findings = []
    url_details = []
    score = 0

    if not urls:
        return {
            "score": 0,
            "findings": [],
            "urls": [],
        }

    for index, url in enumerate(urls):
        parsed = parse_url(url)
        domain = get_domain(url)
        path_and_query = f"{parsed.path} {parsed.query}".lower()
        reasons = []
        url_score = 0

        if parsed.scheme == "http" and url.lower().startswith("http://"):
            url_score += 15
            reasons.append("URL uses insecure HTTP instead of HTTPS")

        if has_ip_address(url):
            url_score += 35
            reasons.append("Raw IP address instead of domain")

        if len(url) > 100:
            url_score += 20
            reasons.append("URL is unusually long")

        if "@" in url:
            url_score += 25
            reasons.append("URL contains '@' symbol")

        if domain.count("-") >= 2:
            url_score += 20
            reasons.append("Excessive hyphens in domain")

        if domain.count(".") >= 4:
            url_score += 15
            reasons.append("URL contains many subdomains")

        if any(word in domain for word in SUSPICIOUS_DOMAIN_WORDS):
            url_score += 15
            reasons.append("Domain contains suspicious phishing keyword")

        if any(word in path_and_query for word in SUSPICIOUS_PATH_WORDS):
            url_score += 15
            reasons.append("URL path contains suspicious action keyword")

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            url_score += 20
            reasons.append("Suspicious top-level domain")

        if domain in URL_SHORTENERS:
            url_score += 20
            reasons.append("Known URL shortener")

        score += url_score

        suspicious = bool(reasons)

        url_details.append(
            {
                "url": url,
                "suspicious": suspicious,
                "reasons": reasons,
            }
        )

        if suspicious:
            severity = "high" if url_score >= 25 else "medium"

            findings.append(
                _build_finding(
                    index=len(findings),
                    severity=severity,
                    detail="; ".join(reasons),
                    evidence=url,
                )
            )

    return {
        "score": min(score, 100),
        "findings": findings,
        "urls": url_details,
    }


def score_urls(text: str) -> tuple[int, list[str], list[str]]:
    """
    Compatibility function for older code.
    Returns:
    - url score
    - reasons
    - extracted URLs
    """

    result = analyse_urls(text)

    reasons = []
    for url_item in result["urls"]:
        reasons.extend(url_item.get("reasons", []))

    return result["score"], reasons, extract_urls(text)


# Compatibility aliases.
analyze_urls = analyse_urls
run_url_rules = analyse_urls
check_url_rules = analyse_urls
