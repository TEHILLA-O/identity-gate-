from __future__ import annotations

SENSITIVE_KEYS = {
    "password",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization",
    "secret",
    "code",
}


def redact(value):
    if isinstance(value, dict):
        password_object = str(value.get("type", "")).lower() == "password"
        cleaned = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in SENSITIVE_KEYS or "token" in lowered or "secret" in lowered or "password" in lowered:
                cleaned[key] = "[redacted]"
            elif password_object and lowered == "value":
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and value.lower().startswith("bearer "):
        return "[redacted]"
    return value
