"""
Redaction pipeline for RECON OSINT.

Ensures that sensitive data (raw passwords, credential hashes, cleartext
password lists) is stripped from TargetEntity metadata before entities
are persisted to the unified audit log.

This is the primary defensibility layer: breach-source adapters may
internally handle raw credential data, but the redaction pipeline
guarantees that data never leaks into the audit trail.
"""

from collections.abc import Mapping
import re
from typing import Any, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from app.schemas.base import TargetEntity

# Metadata keys that MUST be scrubbed before audit-log persistence
SENSITIVE_KEYS = frozenset({
    "password",
    "hashed_password",
    "cleartext_passwords",
    "raw_password",
    "password_hash",
    "credential",
    "secret",
})

# Sentinel value that replaces redacted fields so reviewers know the
# field existed but was intentionally removed.
REDACTED_SENTINEL = "[REDACTED]"


def _normalize_key(key: str) -> str:
    return "".join(character for character in key.casefold() if character.isalnum())


_SENSITIVE_KEY_VARIANTS = frozenset(
    {
        *(_normalize_key(key) for key in SENSITIVE_KEYS),
        "credentials",
        "passwd",
        "apikey",
        "accesstoken",
        "authtoken",
        "bearertoken",
        "authorization",
        "clientsecret",
        "privatekey",
        "refreshtoken",
        "sessiontoken",
        "token",
        "signature",
        "sig",
        "xamzsignature",
        "xamzcredential",
        "xgoogsignature",
        "googlesignature",
        "signedtoken",
        "code",
        "cookie",
        "setcookie",
        "jwt",
    }
)


def _is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and _normalize_key(key) in _SENSITIVE_KEY_VARIANTS


def is_sensitive_key(key: object) -> bool:
    return _is_sensitive_key(key)


def _redact_url(value: str) -> str:
    if not value.casefold().startswith(("http://", "https://")):
        return value
    try:
        parsed = urlsplit(value)
        query = [
            (key, REDACTED_SENTINEL if _is_sensitive_key(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
        fragment = REDACTED_SENTINEL if parsed.fragment else ""
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), fragment))
    except (TypeError, ValueError):
        return value


def _redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: REDACTED_SENTINEL if _is_sensitive_key(key) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, set):
        return {_redact_value(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_redact_value(item) for item in value)
    if isinstance(value, str):
        return _redact_url(value)
    return value


def redact_value(value: Any) -> Any:
    return _redact_value(value)


_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|password|secret|"
    r"authorization|signature|sig|x-amz-signature|x-goog-signature)"
    r"(\s*[=:]\s*)([^\s,;]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def redact_text(value: str) -> str:
    redacted = _URL_PATTERN.sub(lambda match: _redact_url(match.group(0)), value)
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_SENTINEL}",
        redacted,
    )
    return _BEARER_TOKEN.sub(f"Bearer {REDACTED_SENTINEL}", redacted)


def redact_entity(entity: TargetEntity) -> TargetEntity:
    """
    Return a copy of *entity* with all sensitive metadata keys replaced
    by the REDACTED_SENTINEL.

    The original entity is NOT mutated — a shallow copy is returned so
    that in-memory processing can still use the raw data if needed while
    the audit-safe version is what gets persisted.
    """
    clean_metadata = _redact_value(entity.metadata)

    return entity.model_copy(update={"metadata": clean_metadata})


def redact_entities(entities: List[TargetEntity]) -> List[TargetEntity]:
    """
    Convenience wrapper: redact a batch of entities.
    """
    return [redact_entity(e) for e in entities]
