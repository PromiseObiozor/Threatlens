from email.utils import parseaddr


TRUSTED_DOMAINS = {
    "stripe.com",
    "paypal.com",
    "google.com",
    "microsoft.com",
    "github.com",
    "ncirl.ie",
    "revolut.com",
    "wise.com",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

ROLE_WORDS = {
    "security",
    "verify",
    "account",
    "support",
    "admin",
    "billing",
    "update",
    "login",
    "finance",
    "payroll",
    "accounts",
}

BRAND_LOOKALIKE_PATTERNS = {
    "paypal": ["paypa1", "pay-pal", "paypal-", "paypal-support", "paypal-login"],
    "stripe": ["str1pe", "stripe-", "stripe-billing", "stripe-payments"],
    "microsoft": ["micros0ft", "rnicrosoft", "microsoft-support"],
    "google": ["g00gle", "goog1e", "google-security"],
}


def extract_email_domain(email_address: str) -> str:
    """
    Extracts the domain part from an email address.
    Example:
    support@example.com -> example.com
    """
    if not email_address:
        return ""

    _, parsed_email = parseaddr(email_address)

    if "@" not in parsed_email:
        return ""

    return parsed_email.split("@")[-1].lower().strip()


def extract_email_local_part(email_address: str) -> str:
    """
    Extracts the local part before @.
    Example:
    billing@stripe.com -> billing
    """
    if not email_address:
        return ""

    _, parsed_email = parseaddr(email_address)

    if "@" not in parsed_email:
        return ""

    return parsed_email.split("@")[0].lower().strip()


def is_trusted_sender_domain(sender: str) -> bool:
    """
    Checks whether the sender belongs to a known trusted domain.
    This is used to reduce false positives from legitimate senders such as billing@stripe.com.
    """
    sender_domain = extract_email_domain(sender)
    return sender_domain in TRUSTED_DOMAINS


def _contains_brand_lookalike(sender_domain: str) -> tuple[bool, str]:
    """
    Detects obvious brand impersonation patterns.
    Example:
    paypa1-support.com is a PayPal lookalike.
    """
    if not sender_domain:
        return False, ""

    for brand, patterns in BRAND_LOOKALIKE_PATTERNS.items():
        for pattern in patterns:
            if pattern in sender_domain:
                return True, brand

    return False, ""


def score_metadata(sender: str, reply_to: str | None = None) -> tuple[int, list[str]]:
    """
    Scores suspicious email metadata behaviour from 0 to 100.

    Important design decision:
    Words such as 'billing', 'security', and 'support' are not suspicious by themselves.
    They only become suspicious when used with an untrusted, public, or lookalike domain.
    """
    reasons = []
    score = 0

    sender_domain = extract_email_domain(sender)
    sender_local = extract_email_local_part(sender)
    reply_to_domain = extract_email_domain(reply_to) if reply_to else ""

    if not sender_domain:
        score += 20
        reasons.append("Sender email address is missing or invalid")
        return min(score, 100), reasons

    if sender_domain in TRUSTED_DOMAINS:
        if reply_to and reply_to_domain and reply_to_domain != sender_domain:
            score += 35
            reasons.append(
                f"Reply-To domain differs from trusted sender domain: {sender_domain} vs {reply_to_domain}"
            )

        return min(score, 100), reasons

    if reply_to and sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        score += 35
        reasons.append(
            f"Reply-To domain differs from sender domain: {sender_domain} vs {reply_to_domain}"
        )

    is_lookalike, brand = _contains_brand_lookalike(sender_domain)

    if is_lookalike:
        score += 55
        reasons.append(f"Sender domain appears to imitate {brand}: {sender_domain}")

    if sender_domain in FREE_EMAIL_DOMAINS and any(word in sender_local for word in ROLE_WORDS):
        score += 25
        reasons.append(
            f"Role-based sender name used with free email provider: {sender}"
        )

    if any(word in sender_local for word in ROLE_WORDS) and sender_domain not in TRUSTED_DOMAINS:
        score += 10
        reasons.append(f"Role-based sender name from untrusted domain: {sender_local}")

    if any(word in sender_domain for word in ROLE_WORDS) and sender_domain not in TRUSTED_DOMAINS:
        score += 15
        reasons.append(f"Sender domain contains sensitive business keyword: {sender_domain}")

    if sender_domain.count("-") >= 2:
        score += 15
        reasons.append(f"Sender domain contains multiple hyphens: {sender_domain}")

    if sender_domain.count(".") >= 3:
        score += 15
        reasons.append(f"Sender domain has unusual subdomain depth: {sender_domain}")

    return min(score, 100), reasons