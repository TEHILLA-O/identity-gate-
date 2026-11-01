"""OIDC authorization-code + PKCE helper for the sample applications."""

from __future__ import annotations

import hashlib
import secrets
import time
from base64 import urlsafe_b64encode
from datetime import datetime, timezone

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer

from policy.decision import decision, is_allowed, load_matrix


class MemorySessions:
    def __init__(self):
        self.rows: dict[str, dict] = {}

    def put(self, row: dict) -> str:
        key = secrets.token_urlsafe(32)
        self.rows[key] = row
        return key

    def get(self, key: str | None) -> dict | None:
        if not key:
            return None
        row = self.rows.get(key)
        if row and row["expires_at"] <= time.time():
            self.rows.pop(key, None)
            return None
        return row

    def drop(self, key: str | None) -> None:
        if key:
            self.rows.pop(key, None)


class TokenCheck:
    def __init__(self, issuer: str, audience: str, jwks_url: str):
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.keys: dict[str, jwt.PyJWK] = {}
        self.fetched = 0.0

    def verify(self, token: str, *, nonce: str | None = None) -> dict:
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in {"RS256", "ES256"}:
            raise HTTPException(status_code=401, detail="Token algorithm is not accepted.")
        key = self._key(header.get("kid", ""))
        try:
            claims = jwt.decode(token, key.key, algorithms=[header["alg"]], audience=self.audience, issuer=self.issuer, leeway=5)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Token was rejected.") from exc
        if nonce is not None and claims.get("nonce") != nonce:
            raise HTTPException(status_code=401, detail="Login nonce does not match.")
        return claims

    def _key(self, kid: str):
        if kid not in self.keys or time.time() - self.fetched > 600:
            payload = httpx.get(self.jwks_url, timeout=10, trust_env=False).json()
            self.keys = _signing_keys(payload)
            self.fetched = time.time()
        if kid not in self.keys:
            payload = httpx.get(self.jwks_url, timeout=10, trust_env=False).json()
            self.keys = _signing_keys(payload)
            self.fetched = time.time()
        if kid not in self.keys:
            raise HTTPException(status_code=401, detail="Signing key was not found.")
        return self.keys[kid]


def _signing_keys(payload: dict) -> dict[str, jwt.PyJWK]:
    keys: dict[str, jwt.PyJWK] = {}
    for item in payload.get("keys", []):
        if not item.get("kid") or item.get("use") not in {None, "sig"}:
            continue
        try:
            keys[item["kid"]] = jwt.PyJWK(item)
        except jwt.PyJWKError:
            continue
    return keys


def challenge(verifier: str) -> str:
    return urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def roles_from(claims: dict, client_id: str) -> list[str]:
    return list(((claims.get("resource_access") or {}).get(client_id) or {}).get("roles") or [])


def mount_auth(app: FastAPI, config: dict) -> MemorySessions:
    sessions = MemorySessions()
    signer = URLSafeTimedSerializer(config["secret"], salt="demo-oidc")
    checker = TokenCheck(config["issuer"], config["client_id"], f"{config['internal']}/protocol/openid-connect/certs")
    cookie = config["cookie"]

    def current(request: Request, *, refresh: bool = False) -> dict:
        row = sessions.get(request.cookies.get(cookie))
        if row is None:
            raise HTTPException(status_code=401, detail="Authentication is required.")
        if refresh or row["access_exp"] <= time.time() + 15:
            response = httpx.post(
                f"{config['internal']}/protocol/openid-connect/token",
                data={"grant_type": "refresh_token", "refresh_token": row["refresh_token"], "client_id": config["client_id"], "client_secret": config["client_secret"]},
                timeout=15,
                trust_env=False,
            )
            if response.status_code != 200:
                sessions.drop(request.cookies.get(cookie))
                raise HTTPException(status_code=401, detail="The identity session is no longer valid.")
            body = response.json()
            claims = checker.verify(body["access_token"])
            row["access_token"] = body["access_token"]
            row["refresh_token"] = body.get("refresh_token", row["refresh_token"])
            row["roles"] = roles_from(claims, config["client_id"])
            row["access_exp"] = claims["exp"]
        return row

    def require(action: str, *, fresh: bool = False):
        def dependency(request: Request) -> dict:
            row = current(request, refresh=fresh)
            matrix = load_matrix()
            if not is_allowed(matrix, config["application"], action, row["roles"]):
                result = decision(matrix, config["application"], action, row["roles"])
                raise HTTPException(status_code=403, detail=result)
            return row

        return dependency

    app.state.current = current
    app.state.require = require
    app.state.sessions = sessions

    @app.get("/auth/login")
    def login():
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        redirect_uri = f"{config['public']}/auth/callback"
        url = (
            f"{config['public_issuer']}/protocol/openid-connect/auth?client_id={config['client_id']}"
            f"&response_type=code&scope=openid%20profile%20email&redirect_uri={redirect_uri}"
            f"&state={state}&nonce={nonce}&code_challenge={challenge(verifier)}&code_challenge_method=S256"
        )
        response = RedirectResponse(url)
        response.set_cookie(f"{cookie}_state", signer.dumps({"state": state, "nonce": nonce, "verifier": verifier}), httponly=True, samesite="lax", max_age=600)
        return response

    @app.get("/auth/callback")
    def callback(code: str, state: str, request: Request):
        try:
            saved = signer.loads(request.cookies.get(f"{cookie}_state", ""), max_age=600)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Login state is invalid.") from exc
        if saved.get("state") != state:
            raise HTTPException(status_code=400, detail="Login state does not match.")
        redirect_uri = f"{config['public']}/auth/callback"
        token_response = httpx.post(
            f"{config['internal']}/protocol/openid-connect/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "client_id": config["client_id"], "client_secret": config["client_secret"], "code_verifier": saved["verifier"]},
            timeout=20,
            trust_env=False,
        )
        if token_response.status_code != 200:
            raise HTTPException(status_code=401, detail="Token exchange failed.")
        body = token_response.json()
        identity = checker.verify(body["id_token"], nonce=saved["nonce"])
        access = checker.verify(body["access_token"])
        row = {
            "subject": identity.get("sub"),
            "username": identity.get("preferred_username"),
            "email": identity.get("email", ""),
            "roles": roles_from(access, config["client_id"]),
            "access_token": body["access_token"],
            "refresh_token": body.get("refresh_token", ""),
            "id_token": body["id_token"],
            "access_exp": access["exp"],
            "expires_at": time.time() + 1800,
            "csrf": secrets.token_urlsafe(18),
        }
        key = sessions.put(row)
        response = RedirectResponse("/")
        response.set_cookie(cookie, key, httponly=True, samesite="lax")
        response.delete_cookie(f"{cookie}_state")
        return response

    @app.post("/auth/logout")
    def logout(request: Request):
        row = sessions.get(request.cookies.get(cookie))
        if row and request.headers.get("x-csrf-token") != row["csrf"]:
            raise HTTPException(status_code=403, detail="CSRF token is missing or invalid.")
        sessions.drop(request.cookies.get(cookie))
        hint = row["id_token"] if row else ""
        url = f"{config['public_issuer']}/protocol/openid-connect/logout?client_id={config['client_id']}&post_logout_redirect_uri={config['public']}&id_token_hint={hint}"
        response = JSONResponse({"logout_url": url})
        response.delete_cookie(cookie)
        return response

    @app.get("/auth/session")
    def session(request: Request):
        row = current(request, refresh=True)
        return {"username": row["username"], "email": row["email"], "roles": row["roles"], "csrf": row["csrf"]}

    return sessions


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
