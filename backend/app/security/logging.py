import logging
import re

_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]+")
_PASSWORD = re.compile(r"(?i)(password['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)")


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _PASSWORD.sub(r"\1[redacted]", _BEARER.sub(r"\1[redacted]", record.msg))
        return True


def install() -> None:
    logging.getLogger().addFilter(RedactFilter())
