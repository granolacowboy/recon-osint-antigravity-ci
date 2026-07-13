from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.redaction import REDACTED_SENTINEL, redact_entity
from app.schemas.entities import EmailEntity


def test_settings_declare_safe_service_and_policy_defaults() -> None:
    config = Settings(_env_file=None)

    assert config.SHODAN_API_KEY is None
    assert config.REDIS_HOST
    assert config.REDIS_PORT == 6379
    assert config.REDIS_DATABASE == 0
    assert config.REDIS_USERNAME is None
    assert config.REDIS_PASSWORD is None
    assert config.REDIS_SSL is False
    assert config.NEO4J_URI
    assert config.NEO4J_USER
    assert config.NEO4J_PASSWORD is None
    assert config.CORS_ORIGINS
    assert "*" not in config.CORS_ORIGINS
    assert config.MAX_BATCH_SIZE > 0
    assert config.MAX_CONCURRENT_TASKS > 0
    assert config.AUTH_ENABLED is True
    assert config.OIDC_ALGORITHMS == ["RS256"]
    assert config.ALLOW_ACTIVE_SCANNING is False


def test_oidc_algorithm_policy_rejects_symmetric_or_unsigned_tokens() -> None:
    for algorithms in (["HS256"], ["none"]):
        with pytest.raises(ValidationError):
            Settings(OIDC_ALGORITHMS=algorithms, _env_file=None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("DEFAULT_TIMEOUT", 0),
        ("MAX_BATCH_SIZE", 0),
        ("MAX_CONCURRENT_TASKS", 0),
        ("HTTP_MAX_ATTEMPTS", 0),
    ],
)
def test_settings_reject_non_positive_limits(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_redaction_is_recursive_case_insensitive_and_non_mutating() -> None:
    metadata = {
        "Password": "top-secret",
        "safe": {
            "API-Key": "api-secret",
            "provider_url": "https://provider.test/result?api_key=url-secret&q=kept",
            "nested": [
                {"CLIENT_SECRET": "client-secret", "label": "keep-me"},
                {"passwordHash": "hash-secret"},
            ],
        },
        "tuple_data": (
            {"AccessToken": "token-secret"},
            {"safe_value": "still-safe"},
        ),
        "description": "the word password in a value is safe",
    }
    entity = EmailEntity(value="alice@example.com", metadata=metadata)
    original = deepcopy(entity.model_dump())

    clean = redact_entity(entity)

    assert clean.metadata["Password"] == REDACTED_SENTINEL
    assert clean.metadata["safe"]["API-Key"] == REDACTED_SENTINEL
    assert "url-secret" not in clean.metadata["safe"]["provider_url"]
    assert "q=kept" in clean.metadata["safe"]["provider_url"]
    assert (
        clean.metadata["safe"]["nested"][0]["CLIENT_SECRET"]
        == REDACTED_SENTINEL
    )
    assert clean.metadata["safe"]["nested"][0]["label"] == "keep-me"
    assert (
        clean.metadata["safe"]["nested"][1]["passwordHash"]
        == REDACTED_SENTINEL
    )
    assert clean.metadata["tuple_data"][0]["AccessToken"] == REDACTED_SENTINEL
    assert clean.metadata["tuple_data"][1]["safe_value"] == "still-safe"
    assert clean.metadata["description"] == metadata["description"]
    assert entity.model_dump() == original
    assert clean.metadata is not entity.metadata
    assert clean.metadata["safe"] is not entity.metadata["safe"]
