"""Application-layer encryption for sensitive database text columns."""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import JSON, Text, TypeDecorator
from sqlalchemy.dialects.mysql import MEDIUMTEXT


def _key() -> bytes:
    encoded = os.getenv("DATA_ENCRYPTION_KEY", "")
    if not encoded:
        raise RuntimeError("DATA_ENCRYPTION_KEY must be set before saving reports")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as error:
        raise RuntimeError("DATA_ENCRYPTION_KEY must be a URL-safe base64 encoded 32-byte key") from error
    if len(key) != 32:
        raise RuntimeError("DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def encryption_ready() -> bool:
    try:
        _key()
        return True
    except RuntimeError:
        return False


def _encrypt(raw: str) -> str:
    nonce = os.urandom(12)
    encrypted = AESGCM(_key()).encrypt(nonce, raw.encode("utf-8"), None)
    return "csenc:v1:" + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def _decrypt(value: str) -> str:
    payload = base64.urlsafe_b64decode(value.removeprefix("csenc:v1:"))
    return AESGCM(_key()).decrypt(payload[:12], payload[12:], None).decode("utf-8")


class EncryptedText(TypeDecorator):
    """AES-256-GCM encrypted text, with plaintext reads for migration compatibility."""
    impl = Text
    cache_ok = True
    prefix = "csenc:v1:"

    def load_dialect_impl(self, dialect):
        if dialect.name == "mysql":
            return dialect.type_descriptor(MEDIUMTEXT())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return _encrypt(str(value))

    def process_result_value(self, value, dialect):
        if value is None or not value.startswith(self.prefix):
            return value
        return _decrypt(value)


class EncryptedJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return _encrypt(json.dumps(value, separators=(",", ":")))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, str) or not value.startswith("csenc:v1:"):
            return value
        return json.loads(_decrypt(value))
