"""One-off login check. Prints error types only."""

import os
import re
from base64 import urlsafe_b64encode
from hashlib import sha256
import secrets

import httpx
import jwt

from app.config import get_settings
from app.security.tokens import JwksCache, TokenError, TokenVerifier

settings = get_settings()
verifier_value = secrets.token_urlsafe(64)
challenge = urlsafe_b64encode(sha256(verifier_value.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(18)
nonce = secrets.token_urlsafe(18)
redirect_uri = "http://localhost:5173/api/v1/auth/callback"
auth = (
    f"{settings.keycloak_internal_url.rstrip('/')}/realms/{settings.keycloak_realm}/protocol/openid-connect/auth"
    f"?client_id={settings.oidc_client_id}&response_type=code&scope=openid%20profile%20email"
    f"&redirect_uri={redirect_uri}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256"
)
client = httpx.Client(timeout=20, trust_env=False, follow_redirects=False)
page = client.get(auth)
html = page.text
action = re.search(r'action="([^"]+)"', html)
if not action:
    raise SystemExit(f"no login form {page.status_code}")
form = action.group(1).replace("&amp;", "&").replace("http://localhost:8080", settings.keycloak_internal_url.rstrip("/"))
posted = client.post(form, data={"username": "elena.vasquez", "password": os.environ["DEMO_USER_PASSWORD"]})
location = posted.headers.get("location", "")
print("login", posted.status_code, "has_code", "code=" in location)
if "code=" not in location:
    raise SystemExit(posted.text[:180].replace(os.environ["DEMO_USER_PASSWORD"], "***"))
code = location.split("code=", 1)[1].split("&", 1)[0]
token = client.post(
    f"{settings.internal_realm}/protocol/openid-connect/token",
    data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
        "code_verifier": verifier_value,
    },
)
print("token", token.status_code)
body = token.json()
check = TokenVerifier(settings.issuer, [settings.oidc_audience, settings.oidc_client_id], JwksCache(lambda: client.get(f"{settings.internal_realm}/protocol/openid-connect/certs").json()))
for name in ("id_token", "access_token"):
    raw = jwt.decode(body[name], options={"verify_signature": False})
    print(name, "aud", raw.get("aud"), "claims", sorted(raw))
    try:
        check.verify(body[name], nonce=nonce if name == "id_token" else None)
        print(name, "verified")
    except TokenError as exc:
        print(name, type(exc.__cause__).__name__, exc)
client.close()
