from __future__ import annotations

import ast
from pathlib import Path

from scripts.container_checks import validate_deployment


def _public_environment() -> dict[str, str]:
    return {
        "BIND_ADDRESS": "0.0.0.0",
        "AUTH_ENABLED": "true",
        "PUBLIC_API_BASE_URL": "https://api.example.test",
        "REDIS_PASSWORD": "r9vT8KDcwYQ2B5jLxFaU7nP4sGmH6zXe",
        "NEO4J_PASSWORD": "M5hC3Qs8pZkU4rN7xLgB2fVyW9dT6aJe",
        "OPERATIONS_TOKEN": "u6QpT2xW9mFdV7zK3sNgR5bH8cLjY4Ae",
        "OIDC_ISSUER": "https://identity.example.test/",
        "OIDC_AUDIENCE": "https://api.example.test",
        "OIDC_JWKS_URL": "https://identity.example.test/.well-known/jwks.json",
        "OIDC_ALGORITHMS": '["RS256"]',
        "VITE_OIDC_AUTHORITY": "https://identity.example.test",
        "VITE_OIDC_CLIENT_ID": "recon-spa",
        "VITE_OIDC_AUDIENCE": "https://api.example.test",
        "VITE_OIDC_SCOPE": "openid profile email",
        "VITE_OIDC_REDIRECT_URI": "https://recon.example.test/auth/callback",
        "VITE_OIDC_POST_LOGOUT_URI": "https://recon.example.test/",
        "CORS_ORIGINS": '["https://recon.example.test"]',
        "ALLOW_ACTIVE_SCANNING": "false",
        "ACTIVE_TARGET_ALLOWLIST": "[]",
    }


def test_local_unauthenticated_profile_is_allowed() -> None:
    assert validate_deployment(
        {
            "BIND_ADDRESS": "127.0.0.1",
            "AUTH_ENABLED": "false",
            "PUBLIC_API_BASE_URL": "http://127.0.0.1:8000",
        }
    ) == []


def test_public_bind_refuses_unauthenticated_runtime() -> None:
    errors = validate_deployment(
        {
            "BIND_ADDRESS": "0.0.0.0",
            "AUTH_ENABLED": "false",
            "PUBLIC_API_BASE_URL": "https://api.example.test",
        }
    )

    assert any("AUTH_ENABLED=false" in error for error in errors)


def test_public_bind_refuses_browser_loopback_api_and_missing_ops_token() -> None:
    errors = validate_deployment(
        {
            "BIND_ADDRESS": "0.0.0.0",
            "AUTH_ENABLED": "true",
            "PUBLIC_API_BASE_URL": "http://localhost:8000",
        }
    )

    assert any("browser loopback" in error for error in errors)
    assert any("OPERATIONS_TOKEN" in error for error in errors)


def test_authenticated_public_profile_accepts_explicit_external_api() -> None:
    environment = _public_environment()
    environment["BIND_ADDRESS"] = "::"

    assert validate_deployment(environment) == []


def test_public_api_base_url_is_required_and_absolute() -> None:
    missing = validate_deployment(
        {"BIND_ADDRESS": "127.0.0.1", "AUTH_ENABLED": "false"}
    )
    relative = validate_deployment(
        {
            "BIND_ADDRESS": "127.0.0.1",
            "AUTH_ENABLED": "false",
            "PUBLIC_API_BASE_URL": "/api",
        }
    )

    assert any("must be set explicitly" in error for error in missing)
    assert any("absolute HTTP(S) URL" in error for error in relative)


def test_public_profile_requires_https_and_complete_oidc() -> None:
    environment = _public_environment()
    environment["PUBLIC_API_BASE_URL"] = "http://api.example.test"
    environment["OIDC_JWKS_URL"] = ""
    environment["VITE_OIDC_AUTHORITY"] = "https://other.example.test"
    environment["VITE_OIDC_AUDIENCE"] = "different-audience"
    environment["VITE_OIDC_SCOPE"] = "profile email"

    errors = validate_deployment(environment)

    assert any("PUBLIC_API_BASE_URL" in error and "HTTPS" in error for error in errors)
    assert any("OIDC_JWKS_URL must be set" in error for error in errors)
    assert any("AUTHORITY must match" in error for error in errors)
    assert any("AUDIENCE must match" in error for error in errors)
    assert any("must include openid" in error for error in errors)


def test_public_profile_rejects_unsafe_cors_and_redirect_origins() -> None:
    environment = _public_environment()
    environment["CORS_ORIGINS"] = '["https://*.example.test", "http://recon.example.test"]'

    errors = validate_deployment(environment)

    assert any("wildcards" in error for error in errors)
    assert any("CORS_ORIGINS[1]" in error and "HTTPS" in error for error in errors)
    assert any("REDIRECT_URI origin" in error for error in errors)


def test_public_profile_rejects_placeholder_or_reused_secrets() -> None:
    environment = _public_environment()
    environment["REDIS_PASSWORD"] = "REPLACE_WITH_RANDOM_REDIS_PASSWORD"
    environment["NEO4J_PASSWORD"] = environment["OPERATIONS_TOKEN"]

    errors = validate_deployment(environment)

    assert any("REDIS_PASSWORD" in error and "non-placeholder" in error for error in errors)
    assert any("must be distinct" in error for error in errors)


def test_active_scanning_requires_a_narrow_explicit_scope() -> None:
    environment = _public_environment()
    environment["ALLOW_ACTIVE_SCANNING"] = "true"
    environment["ACTIVE_TARGET_ALLOWLIST"] = "[]"

    missing_errors = validate_deployment(environment)

    environment["ACTIVE_TARGET_ALLOWLIST"] = '["0.0.0.0/0"]'
    broad_errors = validate_deployment(environment)

    environment["ACTIVE_TARGET_ALLOWLIST"] = '["example.test"]'
    assert validate_deployment(environment) == []
    assert any("at least one approved scope" in error for error in missing_errors)
    assert any("unrestricted target scope" in error for error in broad_errors)


def test_public_profile_rejects_symmetric_oidc_algorithm() -> None:
    environment = _public_environment()
    environment["OIDC_ALGORITHMS"] = '["HS256"]'

    errors = validate_deployment(environment)

    assert any("approved asymmetric algorithms" in error for error in errors)


def test_frontend_csp_uses_the_exact_built_api_origin() -> None:
    root = Path(__file__).resolve().parents[1]
    nginx = (root / "frontend" / "nginx.conf").read_text(encoding="utf-8")
    dockerfile = (root / "frontend" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "connect-src 'self' __API_ORIGIN__ https:" in nginx
    assert "replaceAll('__API_ORIGIN__', origin)" in dockerfile
    assert "http://127.0.0.1:8000" not in nginx


def test_backend_does_not_import_html_parser() -> None:
    """Keep the CVE-2026-15308 VEX execution-path claim enforceable."""
    root = Path(__file__).resolve().parents[1]
    violations: list[str] = []

    for source_path in sorted((root / "app").rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), source_path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(
                    alias.name == "html.parser" or alias.name.startswith("html.parser.")
                    for alias in node.names
                ):
                    violations.append(f"{source_path.relative_to(root)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "html.parser" or (
                    node.module == "html"
                    and any(alias.name == "parser" for alias in node.names)
                ):
                    violations.append(f"{source_path.relative_to(root)}:{node.lineno}")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Also reject literal dynamic imports such as
                # importlib.import_module("html.parser") and
                # __import__("html.parser"). This deliberately errs on the side
                # of requiring a VEX review if the vulnerable module is ever
                # referenced by first-party runtime code.
                if node.value == "html.parser" or node.value.startswith(
                    "html.parser."
                ):
                    violations.append(f"{source_path.relative_to(root)}:{node.lineno}")

    assert violations == [], (
        "html.parser entered the backend execution path; remove the reference or review "
        "and retire security/recon-api.openvex.json: " + ", ".join(violations)
    )
