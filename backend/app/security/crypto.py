import base64
import hashlib

from cryptography.fernet import Fernet


def cipher(secret: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def seal(secret: str, value: str) -> str:
    return cipher(secret).encrypt(value.encode()).decode()


def open_secret(secret: str, value: str) -> str:
    return cipher(secret).decrypt(value.encode()).decode()
