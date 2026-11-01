import hashlib
import secrets
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import BrowserSession
from app.security.crypto import open_secret, seal
from app.security.tokens import JwksCache, TokenError, TokenVerifier
from app.util import utcnow

ROLE_PERMISSIONS = {
    "identitygate-admin": {"read", "lifecycle:run", "provision:run", "reviews:manage", "reviews:decide", "findings:write", "reports:export", "exceptions:write", "requests:create"},
    "identitygate-operator": {"read", "lifecycle:run", "provision:run", "findings:write", "requests:create"},
    "identitygate-reviewer": {"read", "reviews:decide", "requests:create"},
    "identitygate-auditor": {"read", "reports:export"},
    "identitygate-user": {"read"},
}


class Principal:
    def __init__(self, username: str, roles: list[str], csrf: str | None, session_id: str | None, subject: str = ""):
        self.username = username
        self.roles = roles
        self.csrf = csrf
        self.session_id = session_id
        self.subject = subject

    def allows(self, *permissions: str) -> bool:
        held = set()
        for role in self.roles:
            held |= ROLE_PERMISSIONS.get(role, set())
        return set(permissions).issubset(held)


def serializer():
    return URLSafeTimedSerializer(get_settings().session_secret, salt="identitygate-oidc")


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode()


def verifier() -> TokenVerifier:
    settings = get_settings()

    def fetch() -> dict:
        response = httpx.get(f"{settings.internal_realm}/protocol/openid-connect/certs", timeout=10, trust_env=False)
        response.raise_for_status()
        return response.json()

    return TokenVerifier(settings.issuer, [settings.oidc_audience, settings.oidc_client_id], JwksCache(fetch))


def _roles(claims: dict) -> list[str]:
    return list((claims.get("realm_access") or {}).get("roles") or [])


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    settings = get_settings()
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        try:
            claims = verifier().verify(header.split(" ", 1)[1])
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        username = claims.get("preferred_username") or claims.get("sub")
        return Principal(username, _roles(claims), None, None, claims.get("sub", ""))
    session_id = request.cookies.get("ig_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Authentication is required.")
    row = db.get(BrowserSession, session_id)
    if row is None:
        raise HTTPException(status_code=401, detail="Session is not recognised.")
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if expires <= utcnow():
        db.delete(row)
        raise HTTPException(status_code=401, detail="Session has expired.")
    access_exp = row.access_expires_at if row.access_expires_at.tzinfo else row.access_expires_at.replace(tzinfo=timezone.utc)
    if access_exp <= utcnow() + timedelta(seconds=20):
        _refresh(db, row, settings)
    if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("x-csrf-token") != row.csrf_token:
        raise HTTPException(status_code=403, detail="CSRF token is missing or invalid.")
    return Principal(row.username, list(row.roles or []), row.csrf_token, row.id, row.subject)


def require(*permissions: str):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.allows(*permissions):
            raise HTTPException(status_code=403, detail="This action is not allowed for the current roles.")
        return principal

    return dependency


def _refresh(db: Session, row: BrowserSession, settings) -> None:
    response = httpx.post(
        f"{settings.internal_realm}/protocol/openid-connect/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": open_secret(settings.session_secret, row.refresh_token),
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
        },
        timeout=15,
        trust_env=False,
    )
    if response.status_code != 200:
        db.delete(row)
        db.commit()
        raise HTTPException(status_code=401, detail="The identity session is no longer valid.")
    body = response.json()
    try:
        claims = verifier().verify(body["access_token"])
    except TokenError as exc:
        db.delete(row)
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    row.access_token = seal(settings.session_secret, body["access_token"])
    if body.get("refresh_token"):
        row.refresh_token = seal(settings.session_secret, body["refresh_token"])
    row.roles = _roles(claims)
    row.access_expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    row.expires_at = utcnow() + timedelta(minutes=30)
    db.commit()


def new_session(db: Session, claims: dict, access_token: str, refresh_token: str, id_token: str) -> BrowserSession:
    settings = get_settings()
    row = BrowserSession(
        id=secrets.token_urlsafe(32),
        subject=claims.get("sub", ""),
        username=claims.get("preferred_username") or claims.get("sub"),
        email=claims.get("email") or "",
        roles=_roles(claims),
        access_token=seal(settings.session_secret, access_token),
        refresh_token=seal(settings.session_secret, refresh_token or ""),
        id_token=seal(settings.session_secret, id_token or ""),
        access_expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        csrf_token=secrets.token_urlsafe(24),
        created_at=utcnow(),
        expires_at=utcnow() + timedelta(minutes=30),
    )
    db.add(row)
    db.flush()
    return row


def read_state(cookie: str | None) -> dict:
    if not cookie:
        raise HTTPException(status_code=400, detail="Login state is missing.")
    try:
        return serializer().loads(cookie, max_age=600)
    except (BadSignature, SignatureExpired) as exc:
        raise HTTPException(status_code=400, detail="Login state is invalid.") from exc
