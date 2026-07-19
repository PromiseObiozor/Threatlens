import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import User


JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60
JWT_SECRET = os.getenv("THREATLENS_JWT_SECRET") or secrets.token_urlsafe(32)
PASSWORD_ITERATIONS = 120_000

security = HTTPBearer(auto_error=False)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PASSWORD_ITERATIONS,
    ).hex()

    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected_digest = password_hash.split("$")
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        int(iterations),
    ).hex()

    return hmac.compare_digest(digest, expected_digest)


def get_user_by_username(db: Session, username: str) -> User | None:
    normalized_username = _normalize_username(username)

    return (
        db.query(User)
        .filter(User.username == normalized_username)
        .first()
    )


def register_user(
    db: Session,
    username: str,
    password: str,
) -> dict[str, str]:
    normalized_username = _normalize_username(username)

    if not normalized_username:
        raise ValueError("Username is required")

    existing_user = get_user_by_username(db, normalized_username)

    if existing_user is not None:
        raise ValueError("Username is already registered")

    user = User(
        username=normalized_username,
        hashed_password=hash_password(password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"username": user.username}


def authenticate_user(
    db: Session,
    username: str,
    password: str,
) -> dict[str, str] | None:
    user = get_user_by_username(db, username)

    if user is None:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return {"username": user.username}


def create_access_token(username: str) -> str:
    header = {
        "alg": JWT_ALGORITHM,
        "typ": "JWT",
    }

    payload = {
        "sub": _normalize_username(username),
        "exp": int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS,
    }

    encoded_header = _base64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )

    encoded_payload = _base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )

    unsigned_token = f"{encoded_header}.{encoded_payload}"

    signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        unsigned_token.encode("ascii"),
        hashlib.sha256,
    ).digest()

    return f"{unsigned_token}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as error:
        raise ValueError("Invalid token format") from error

    unsigned_token = f"{encoded_header}.{encoded_payload}"

    expected_signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        unsigned_token.encode("ascii"),
        hashlib.sha256,
    ).digest()

    provided_signature = _base64url_decode(encoded_signature)

    if not hmac.compare_digest(expected_signature, provided_signature):
        raise ValueError("Invalid token signature")

    payload = json.loads(_base64url_decode(encoded_payload))

    if payload.get("exp", 0) < int(time.time()):
        raise ValueError("Token has expired")

    if not payload.get("sub"):
        raise ValueError("Token subject is missing")

    return payload


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    username = _normalize_username(payload["sub"])
    user = get_user_by_username(db, username)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
