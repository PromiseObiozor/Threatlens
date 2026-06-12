from email.utils import parseaddr


SUSPICIOUS_SENDER_WORDS = [
    "security",
    "verify",
    "account",
    "support",
    "admin",
    "billing",
    "update",
    "login",
]


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


def score_metadata(sender: str, reply_to: str | None = None) -> tuple[int, list[str]]:
    """
    Scores suspicious metadata behaviour from 0 to 100.
    """
    reasons = []
    score = 0

    sender_domain = extract_email_domain(sender)
    reply_to_domain = extract_email_domain(reply_to) if reply_to else ""

    if reply_to and sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        score += 40
        reasons.append(
            f"Reply-To domain differs from sender domain: {sender_domain} vs {reply_to_domain}"
        )

    lower_sender = sender.lower() if sender else ""

    for word in SUSPICIOUS_SENDER_WORDS:
        if word in lower_sender:
            score += 10
            reasons.append(f"Sender contains suspicious keyword: {word}")
            break

    if sender_domain and sender_domain.count("-") >= 2:
        score += 15
        reasons.append(f"Sender domain contains multiple hyphens: {sender_domain}")

    if sender_domain and sender_domain.count(".") >= 3:
        score += 15
        reasons.append(f"Sender domain has unusual subdomain depth: {sender_domain}")

    return min(score, 100), reasons