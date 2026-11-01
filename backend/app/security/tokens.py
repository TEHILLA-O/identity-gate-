"""JWT verification. Unsigned tokens and untrusted algorithms are rejected."""

from __future__ import annotations

import time
from typing import Callable

import jwt
from jwt import PyJWK


class TokenError(Exception):
    pass


class JwksCache:
    def __init__(self, fetcher: Callable[[], dict], min_refresh: float = 30, max_age: float = 600):
        self.fetcher = fetcher
        self.min_refresh = min_refresh
        self.max_age = max_age
        self.keys: dict[str, PyJWK] = {}
        self.fetched_at = 0.0

    def get(self, kid: str) -> PyJWK:
        key = self.keys.get(kid)
        if key and time.time() - self.fetched_at < self.max_age:
            return key
        self.refresh(force=key is None)
        key = self.keys.get(kid)
        if not key:
            raise TokenError("Signing key is not published by the issuer.")
        return key

    def refresh(self, force: bool = False) -> None:
        if not force and time.time() - self.fetched_at < self.min_refresh:
            return
        payload = self.fetcher()
        self.keys = _signing_keys(payload)
        self.fetched_at = time.time()


def _signing_keys(payload: dict) -> dict[str, PyJWK]:
    keys: dict[str, PyJWK] = {}
    for item in payload.get("keys", []):
        if not item.get("kid") or item.get("use") not in {None, "sig"}:
            continue
        try:
            keys[item["kid"]] = PyJWK(item)
        except jwt.PyJWKError:
            continue
    return keys


class TokenVerifier:
    def __init__(self, issuer: str, audience: str | list[str], jwks: JwksCache):
        self.issuer = issuer
        self.audience = audience
        self.jwks = jwks

    def verify(self, token: str, *, nonce: str | None = None) -> dict:
        if not token or token.count(".") != 2:
            raise TokenError("Token is malformed.")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("Token header could not be read.") from exc
        algorithm = header.get("alg")
        if algorithm not in {"RS256", "ES256"}:
            raise TokenError("Token algorithm is not accepted.")
        key = self.jwks.get(header.get("kid", ""))
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
                leeway=5,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("Token is expired.") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenError("Token issuer is not trusted.") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenError("Token audience is not accepted.") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenError("Token is not valid yet.") from exc
        except jwt.PyJWTError as exc:
            raise TokenError("Token signature is invalid.") from exc
        if nonce is not None and claims.get("nonce") != nonce:
            raise TokenError("Token nonce does not match the login request.")
        if not claims.get("sub") and not claims.get("preferred_username"):
            raise TokenError("Token has no subject.")
        return claims
