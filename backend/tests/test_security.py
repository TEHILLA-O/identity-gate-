import json
import logging
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.crypto import open_secret, seal
from app.security.logging import RedactFilter
from app.security.redact import redact
from app.security.tokens import JwksCache, TokenError, TokenVerifier


def test_redact_strips_secrets_from_bodies():
    cleaned = redact(
        {
            "authorization": "Bearer abc.def.ghi",
            "nested": {"client_secret": "super", "department": "Finance"},
            "note": "Bearer abc.def.ghi",
        }
    )
    assert cleaned["authorization"] == "[redacted]"
    assert cleaned["nested"]["client_secret"] == "[redacted]"
    assert cleaned["nested"]["department"] == "Finance"
    assert cleaned["note"] == "[redacted]"


def test_log_filter_removes_bearer_and_password(caplog):
    logger = logging.getLogger("identitygate.test.redact")
    logger.addFilter(RedactFilter())
    logger.setLevel(logging.INFO)
    with caplog.at_level(logging.INFO):
        logger.info("Authorization: Bearer aaa.bbb.ccc password=swordfish")
    assert "swordfish" not in caplog.text
    assert "aaa.bbb.ccc" not in caplog.text
    assert "[redacted]" in caplog.text


def _rsa_jwk():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
        encryption_algorithm=__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]
        ).NoEncryption(),
    )
    numbers = key.public_key().public_numbers()
    import base64

    def b64(data: int) -> str:
        raw = data.to_bytes((data.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    jwk = {"kty": "RSA", "kid": "test-key", "alg": "RS256", "n": b64(numbers.n), "e": b64(numbers.e), "use": "sig"}
    return private, jwk


def _verifier(jwk, audience="identitygate-api", issuer="http://localhost:8080/realms/northstar"):
    return TokenVerifier(issuer, audience, JwksCache(lambda: {"keys": [jwk]}, min_refresh=0))


def _token(private, claims, alg="RS256", kid="test-key"):
    return jwt.encode(claims, private, algorithm=alg, headers={"kid": kid})


def test_rejects_bad_signature_audience_issuer_and_expiry():
    private, jwk = _rsa_jwk()
    verifier = _verifier(jwk)
    now = int(time.time())
    good = {"sub": "user", "iss": "http://localhost:8080/realms/northstar", "aud": "identitygate-api", "exp": now + 60, "iat": now}
    claims = verifier.verify(_token(private, good))
    assert claims["sub"] == "user"
    other, _ = _rsa_jwk()
    try:
        verifier.verify(_token(other, good))
        assert False
    except TokenError as exc:
        assert "signature" in str(exc).lower()
    try:
        verifier.verify(_token(private, {**good, "aud": "other-api"}))
        assert False
    except TokenError as exc:
        assert "audience" in str(exc).lower()
    try:
        verifier.verify(_token(private, {**good, "iss": "http://evil.example/realms/northstar"}))
        assert False
    except TokenError as exc:
        assert "issuer" in str(exc).lower()
    try:
        verifier.verify(_token(private, {**good, "exp": now - 30}))
        assert False
    except TokenError as exc:
        assert "expired" in str(exc).lower()


def test_rejects_unsigned_tokens():
    private, jwk = _rsa_jwk()
    verifier = _verifier(jwk)
    now = int(time.time())
    claims = {"sub": "user", "iss": verifier.issuer, "aud": "identitygate-api", "exp": now + 60}
    body = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})
    header, payload, _sig = body.split(".")
    unsigned = f"{header}.{payload}."
    try:
        verifier.verify(unsigned)
        assert False
    except TokenError:
        pass
    none_header = json.dumps({"alg": "none", "kid": "test-key"}).encode()
    import base64

    forged = base64.urlsafe_b64encode(none_header).rstrip(b"=").decode() + "." + payload + "."
    try:
        verifier.verify(forged)
        assert False
    except TokenError as exc:
        assert "algorithm" in str(exc).lower() or "malformed" in str(exc).lower() or "header" in str(exc).lower()


def test_session_tokens_are_encrypted_at_rest():
    hidden = seal("session-secret", "access-token-value")
    assert "access-token-value" not in hidden
    assert open_secret("session-secret", hidden) == "access-token-value"
