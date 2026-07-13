from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.auth import AuthenticationError, OIDCVerifier
from app.core.config import Settings


@dataclass(frozen=True)
class _SigningKey:
    key: object


class _StaticJWKClient:
    def __init__(self, key: object) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> _SigningKey:
        return _SigningKey(self._key)


@pytest.fixture(scope="module")
def rsa_keys() -> tuple[object, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _settings() -> Settings:
    return Settings(
        AUTH_ENABLED=True,
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/.well-known/jwks.json",
        OIDC_ALGORITHMS=["RS256"],
        _env_file=None,
    )


def _claims(**updates: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
        "sub": "investigator-1",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iss": "https://issuer.example.test/",
        "aud": "recon-api",
        "roles": ["analyst", "recon-admin"],
    }
    claims.update(updates)
    return claims


def test_oidc_verifier_accepts_valid_fixed_algorithm_token(rsa_keys) -> None:
    private_key, public_key = rsa_keys
    token = jwt.encode(
        _claims(), private_key, algorithm="RS256", headers={"kid": "local-test"}
    )

    principal = OIDCVerifier(
        _settings(), jwk_client=_StaticJWKClient(public_key)
    ).verify(token)

    assert principal.subject == "investigator-1"
    assert principal.roles == frozenset({"analyst", "recon-admin"})


def test_oidc_verifier_never_accepts_token_selected_algorithm() -> None:
    secret = "test-shared-secret-with-at-least-32-bytes"
    token = jwt.encode(_claims(), secret, algorithm="HS256")

    with pytest.raises(AuthenticationError):
        OIDCVerifier(
            _settings(), jwk_client=_StaticJWKClient(secret)
        ).verify(token)


@pytest.mark.parametrize("missing_claim", ["sub", "exp", "iat"])
def test_oidc_verifier_requires_security_claims(
    rsa_keys, missing_claim: str
) -> None:
    private_key, public_key = rsa_keys
    claims = _claims()
    claims.pop(missing_claim)
    token = jwt.encode(claims, private_key, algorithm="RS256")

    with pytest.raises(AuthenticationError):
        OIDCVerifier(
            _settings(), jwk_client=_StaticJWKClient(public_key)
        ).verify(token)


@pytest.mark.parametrize(
    "claim,value",
    [("iss", "https://wrong-issuer.example/"), ("aud", "wrong-audience")],
)
def test_oidc_verifier_validates_issuer_and_audience(
    rsa_keys, claim: str, value: str
) -> None:
    private_key, public_key = rsa_keys
    token = jwt.encode(
        _claims(**{claim: value}), private_key, algorithm="RS256"
    )

    with pytest.raises(AuthenticationError):
        OIDCVerifier(
            _settings(), jwk_client=_StaticJWKClient(public_key)
        ).verify(token)


def test_enabled_authentication_rejects_incomplete_oidc_configuration() -> None:
    with pytest.raises(ValueError, match="OIDC"):
        OIDCVerifier(Settings(AUTH_ENABLED=True, _env_file=None))
