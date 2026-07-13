"""Container deployment preflight and service-specific health probes."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.request
from collections.abc import Mapping
from urllib.parse import urlparse


TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})
ASYMMETRIC_JWT_ALGORITHMS = frozenset(
    {
        "EdDSA",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "RS256",
        "RS384",
        "RS512",
    }
)
PLACEHOLDER_SECRET_MARKERS = frozenset(
    {
        "change-me",
        "changeme",
        "ci-not-used",
        "default",
        "example",
        "operations-secret",
        "password",
        "replace_with",
        "secret",
    }
)


def _parse_bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be true or false")


def _is_loopback_host(value: str) -> bool:
    host = value.strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_non_public_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


def _parse_json_list(
    environment: Mapping[str, str], name: str, errors: list[str]
) -> list[str]:
    raw_value = environment.get(name, "").strip()
    try:
        value = json.loads(raw_value)
    except (json.JSONDecodeError, TypeError):
        errors.append(f"{name} must be a JSON array")
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        errors.append(f"{name} must be a JSON array of non-empty strings")
        return []
    return [item.strip() for item in value]


def _validate_https_url(
    name: str,
    value: str,
    errors: list[str],
    *,
    origin_only: bool = False,
) -> str | None:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        errors.append(f"{name} must be a valid HTTPS URL")
        return None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        errors.append(f"{name} must be a credential-free HTTPS URL")
        return None
    if _is_loopback_host(hostname) or _is_non_public_ip(hostname):
        errors.append(f"{name} must use a public, non-loopback host")
        return None
    if origin_only and parsed.path not in {"", "/"}:
        errors.append(f"{name} must be an origin without a path")
        return None
    default_port = port in {None, 443}
    authority = hostname if default_port else f"{hostname}:{port}"
    return f"https://{authority}"


def _validate_strong_secret(
    environment: Mapping[str, str], name: str, errors: list[str]
) -> str:
    value = environment.get(name, "").strip()
    normalized = value.casefold()
    if not value:
        errors.append(f"{name} must be set for a public deployment")
    elif (
        len(value) < 32
        or len(set(value)) < 12
        or any(marker in normalized for marker in PLACEHOLDER_SECRET_MARKERS)
    ):
        errors.append(
            f"{name} must be a non-placeholder secret with at least 32 "
            "characters of strong randomness"
        )
    return value


def validate_deployment(environment: Mapping[str, str]) -> list[str]:
    """Return non-sensitive deployment policy violations."""
    errors: list[str] = []
    bind_address = environment.get("BIND_ADDRESS", "127.0.0.1").strip()
    auth_value = environment.get("AUTH_ENABLED", "true")
    public_api_base_url = environment.get("PUBLIC_API_BASE_URL", "").strip()

    try:
        auth_enabled = _parse_bool(auth_value, "AUTH_ENABLED")
    except ValueError as exc:
        errors.append(str(exc))
        auth_enabled = True

    public_bind = not _is_loopback_host(bind_address)
    if public_bind and not auth_enabled:
        errors.append(
            "AUTH_ENABLED=false is allowed only with a loopback BIND_ADDRESS"
        )

    if not public_api_base_url:
        errors.append("PUBLIC_API_BASE_URL must be set explicitly")
    else:
        parsed = urlparse(public_api_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            errors.append(
                "PUBLIC_API_BASE_URL must be an absolute HTTP(S) URL"
            )
        elif public_bind and _is_loopback_host(parsed.hostname):
            errors.append(
                "PUBLIC_API_BASE_URL cannot use browser loopback when "
                "BIND_ADDRESS is non-loopback"
            )

    try:
        active_scanning = _parse_bool(
            environment.get("ALLOW_ACTIVE_SCANNING", "false"),
            "ALLOW_ACTIVE_SCANNING",
        )
    except ValueError as exc:
        errors.append(str(exc))
        active_scanning = False

    if active_scanning:
        active_scope = _parse_json_list(
            environment, "ACTIVE_TARGET_ALLOWLIST", errors
        )
        if not active_scope:
            errors.append(
                "ACTIVE_TARGET_ALLOWLIST must contain at least one approved scope "
                "when active scanning is enabled"
            )
        elif any(scope in {"*", "0.0.0.0/0", "::/0"} for scope in active_scope):
            errors.append(
                "ACTIVE_TARGET_ALLOWLIST cannot grant an unrestricted target scope"
            )

    if public_bind:
        if public_api_base_url:
            _validate_https_url(
                "PUBLIC_API_BASE_URL", public_api_base_url, errors
            )

        required_oidc = (
            "OIDC_ISSUER",
            "OIDC_AUDIENCE",
            "OIDC_JWKS_URL",
            "VITE_OIDC_AUTHORITY",
            "VITE_OIDC_CLIENT_ID",
            "VITE_OIDC_AUDIENCE",
            "VITE_OIDC_SCOPE",
            "VITE_OIDC_REDIRECT_URI",
            "VITE_OIDC_POST_LOGOUT_URI",
        )
        for name in required_oidc:
            if not environment.get(name, "").strip():
                errors.append(f"{name} must be set for a public deployment")

        issuer = environment.get("OIDC_ISSUER", "").strip()
        authority = environment.get("VITE_OIDC_AUTHORITY", "").strip()
        jwks_url = environment.get("OIDC_JWKS_URL", "").strip()
        redirect_uri = environment.get("VITE_OIDC_REDIRECT_URI", "").strip()
        logout_uri = environment.get("VITE_OIDC_POST_LOGOUT_URI", "").strip()
        if issuer:
            _validate_https_url("OIDC_ISSUER", issuer, errors)
        if authority:
            _validate_https_url("VITE_OIDC_AUTHORITY", authority, errors)
        if jwks_url:
            _validate_https_url("OIDC_JWKS_URL", jwks_url, errors)
        redirect_origin = (
            _validate_https_url(
                "VITE_OIDC_REDIRECT_URI", redirect_uri, errors
            )
            if redirect_uri
            else None
        )
        logout_origin = (
            _validate_https_url(
                "VITE_OIDC_POST_LOGOUT_URI", logout_uri, errors
            )
            if logout_uri
            else None
        )
        if issuer and authority and issuer.rstrip("/") != authority.rstrip("/"):
            errors.append("VITE_OIDC_AUTHORITY must match OIDC_ISSUER")
        oidc_audience = environment.get("OIDC_AUDIENCE", "").strip()
        vite_audience = environment.get("VITE_OIDC_AUDIENCE", "").strip()
        if oidc_audience and vite_audience and oidc_audience != vite_audience:
            errors.append("VITE_OIDC_AUDIENCE must match OIDC_AUDIENCE")
        scope = environment.get("VITE_OIDC_SCOPE", "").split()
        if scope and "openid" not in scope:
            errors.append("VITE_OIDC_SCOPE must include openid")

        algorithms = _parse_json_list(environment, "OIDC_ALGORITHMS", errors)
        if algorithms and not set(algorithms).issubset(ASYMMETRIC_JWT_ALGORITHMS):
            errors.append(
                "OIDC_ALGORITHMS must contain only approved asymmetric algorithms"
            )

        cors_origins = _parse_json_list(environment, "CORS_ORIGINS", errors)
        normalized_origins: set[str] = set()
        for index, origin in enumerate(cors_origins):
            if "*" in origin:
                errors.append("CORS_ORIGINS cannot contain wildcards")
                continue
            normalized = _validate_https_url(
                f"CORS_ORIGINS[{index}]", origin, errors, origin_only=True
            )
            if normalized:
                normalized_origins.add(normalized)
        if not cors_origins:
            errors.append("CORS_ORIGINS must contain at least one HTTPS origin")
        for name, uri_origin in (
            ("VITE_OIDC_REDIRECT_URI", redirect_origin),
            ("VITE_OIDC_POST_LOGOUT_URI", logout_origin),
        ):
            if uri_origin and uri_origin not in normalized_origins:
                errors.append(f"{name} origin must be listed in CORS_ORIGINS")

        secrets = {
            name: _validate_strong_secret(environment, name, errors)
            for name in ("REDIS_PASSWORD", "NEO4J_PASSWORD", "OPERATIONS_TOKEN")
        }
        populated_secrets = [value for value in secrets.values() if value]
        if len(populated_secrets) != len(set(populated_secrets)):
            errors.append(
                "REDIS_PASSWORD, NEO4J_PASSWORD, and OPERATIONS_TOKEN must be distinct"
            )
    return errors


def check_api_readiness(environment: Mapping[str, str]) -> bool:
    headers: dict[str, str] = {}
    operations_token = environment.get("OPERATIONS_TOKEN", "").strip()
    if operations_token:
        headers["X-Operations-Token"] = operations_token
    request = urllib.request.Request(
        "http://127.0.0.1:8000/health/ready",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status == 200
    except Exception:
        return False


def check_worker_heartbeat(environment: Mapping[str, str]) -> bool:
    try:
        from arq.constants import default_queue_name, health_check_key_suffix
        from redis import Redis

        client = Redis(
            host=environment.get("REDIS_HOST", "redis"),
            port=int(environment.get("REDIS_PORT", "6379")),
            db=int(environment.get("REDIS_DATABASE", "0")),
            username=environment.get("REDIS_USERNAME") or None,
            password=environment.get("REDIS_PASSWORD") or None,
            ssl=_parse_bool(environment.get("REDIS_SSL", "false"), "REDIS_SSL"),
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        try:
            heartbeat_key = default_queue_name + health_check_key_suffix
            return bool(client.ping() and client.exists(heartbeat_key))
        finally:
            client.close()
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    mode = arguments[0] if arguments else ""
    if mode == "validate":
        errors = validate_deployment(os.environ)
        for error in errors:
            print(f"deployment configuration error: {error}", file=sys.stderr)
        return int(bool(errors))
    if mode == "api":
        return int(not check_api_readiness(os.environ))
    if mode == "worker":
        return int(not check_worker_heartbeat(os.environ))
    print("usage: container_checks.py {validate|api|worker}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
