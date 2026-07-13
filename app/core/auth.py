from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import jwt
from jwt import PyJWKClient

from app.core.config import Settings


class AuthenticationError(ValueError):
    """A bearer token could not be authenticated."""


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str] = frozenset()
    expires_at: int | None = None


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal: ...


class OIDCVerifier:
    """Validate OIDC access tokens against an explicit server-side policy."""

    def __init__(self, config: Settings, *, jwk_client: object | None = None) -> None:
        missing = [
            name
            for name in ("OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_JWKS_URL")
            if not getattr(config, name, None)
        ]
        if missing:
            raise ValueError(
                "OIDC authentication configuration is incomplete: "
                + ", ".join(missing)
            )
        self._issuer = str(config.OIDC_ISSUER)
        self._audience = str(config.OIDC_AUDIENCE)
        self._algorithms = tuple(config.OIDC_ALGORITHMS)
        self._leeway = config.OIDC_LEEWAY_SECONDS
        self._roles_claim = config.OIDC_ROLES_CLAIM
        self._jwk_client = jwk_client or PyJWKClient(
            str(config.OIDC_JWKS_URL),
            cache_keys=True,
            cache_jwk_set=True,
            lifespan=config.OIDC_JWKS_CACHE_SECONDS,
            timeout=config.OIDC_JWKS_TIMEOUT_SECONDS,
        )

    def verify(self, token: str) -> Principal:
        if not token:
            raise AuthenticationError("bearer token is missing")
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._algorithms),
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": ["sub", "exp", "iat"]},
            )
        except Exception as exc:
            raise AuthenticationError("bearer token is invalid") from exc

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("bearer token subject is invalid")
        raw_roles = claims.get(self._roles_claim, ())
        if isinstance(raw_roles, str):
            roles = frozenset(part for part in raw_roles.split() if part)
        elif isinstance(raw_roles, (list, tuple, set, frozenset)):
            roles = frozenset(role for role in raw_roles if isinstance(role, str))
        else:
            roles = frozenset()
        expires_at = claims.get("exp")
        if not isinstance(expires_at, int):
            raise AuthenticationError("bearer token expiry is invalid")
        return Principal(subject=subject, roles=roles, expires_at=expires_at)
