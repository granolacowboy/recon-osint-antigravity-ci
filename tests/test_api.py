from __future__ import annotations

import asyncio
import warnings
from dataclasses import dataclass

import pytest

from starlette.exceptions import StarletteDeprecationWarning

warnings.filterwarnings(
    "ignore",
    message="Using `httpx` with `starlette.testclient` is deprecated.*",
    category=StarletteDeprecationWarning,
)
from fastapi.testclient import TestClient

from app.core.auth import AuthenticationError, Principal
from app.core.config import Settings
from app.core.queueing import InMemoryScanQueue, QueueError
from app.core.rate_limit import InMemoryRateLimiter
from app.main import ServiceContainer, _repair_production_services, create_app
from app.schemas.outcomes import AdapterState
from app.schemas.platform import (
    AdapterRun,
    Case,
    GraphNode,
    Provenance,
    Scan,
    ScanState,
    ScanTarget,
)
from app.storage.base import StoreError
from app.storage.memory import InMemoryStore


@dataclass
class _TokenVerifier:
    principals: dict[str, Principal]

    def verify(self, token: str) -> Principal:
        try:
            return self.principals[token]
        except KeyError as exc:
            raise AuthenticationError("invalid test token") from exc


class _UnhealthyQueue(InMemoryScanQueue):
    async def health(self) -> bool:
        return False


class _FailingQueue(InMemoryScanQueue):
    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str:
        raise QueueError("redis unavailable")


class _PendingAbortQueue(InMemoryScanQueue):
    async def abort(self, job_id: str) -> bool:
        self.aborted_job_ids.append(job_id)
        return False


class _FailingAbortQueue(InMemoryScanQueue):
    async def abort(self, job_id: str) -> bool:
        raise QueueError("redis unavailable")


class _ConcurrentCancellationQueue(InMemoryScanQueue):
    def __init__(self, store: InMemoryStore) -> None:
        super().__init__()
        self.store = store

    async def abort(self, job_id: str) -> bool:
        await self.store.acknowledge_cancellation(
            "owner-a", self.jobs[job_id]
        )
        return False


class _FailingListStore(InMemoryStore):
    async def list_cases(
        self, owner_id: str, *, offset: int = 0, limit: int
    ) -> list[Case]:
        raise StoreError("database unavailable")


class _FailingCancellationStore(InMemoryStore):
    async def request_cancellation(self, owner_id: str, scan_id: str):
        raise StoreError("database unavailable")


class _RecoveringStore(InMemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.health_checks = 0
        self.initialize_calls = 0

    async def health(self) -> bool:
        self.health_checks += 1
        return self.health_checks > 1

    async def initialize(self) -> None:
        self.initialize_calls += 1


class _UnhealthyRateLimiter(InMemoryRateLimiter):
    async def health(self) -> bool:
        return False


def _headers(token: str = "owner-a-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _client(
    *,
    config: Settings | None = None,
    store: InMemoryStore | None = None,
    queue: InMemoryScanQueue | None = None,
    limiter: InMemoryRateLimiter | None = None,
) -> tuple[TestClient, InMemoryStore, InMemoryScanQueue]:
    config = config or Settings(
        AUTH_ENABLED=True,
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        OPERATIONS_TOKEN="test-operations-token",
        _env_file=None,
    )
    store = store or InMemoryStore()
    queue = queue or InMemoryScanQueue()
    verifier = _TokenVerifier(
        {
            "owner-a-token": Principal("owner-a", frozenset({"analyst"})),
            "owner-b-token": Principal("owner-b", frozenset({"analyst"})),
            "admin-token": Principal(
                "owner-admin", frozenset({config.OIDC_ADMIN_ROLE})
            ),
        }
    )
    app = create_app(
        config,
        store=store,
        queue=queue,
        rate_limiter=limiter or InMemoryRateLimiter(1000, 60),
        verifier=verifier,
    )
    return TestClient(app), store, queue


def _create_case(client: TestClient, token: str = "owner-a-token") -> dict:
    response = client.post(
        "/v1/cases", json={"name": "Acme inquiry"}, headers=_headers(token)
    )
    assert response.status_code == 201
    return response.json()


def test_unauthenticated_request_is_rejected() -> None:
    client, _, _ = _client()

    response = client.get("/v1/cases")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_explicit_auth_disabled_mode_uses_fixed_local_principal() -> None:
    config = Settings(
        AUTH_ENABLED=False,
        LOCAL_PRINCIPAL_SUB="explicit-local-user",
        _env_file=None,
    )
    client, _, _ = _client(config=config)

    response = client.post("/v1/cases", json={"name": "Local case"})

    assert response.status_code == 201
    assert response.json()["owner_id"] == "explicit-local-user"


def test_valid_principal_can_create_and_list_only_owned_cases() -> None:
    client, _, _ = _client()
    owned = _create_case(client)
    _create_case(client, "owner-b-token")

    response = client.get("/v1/cases", headers=_headers())
    oversized = client.get("/v1/cases?limit=101", headers=_headers())

    assert response.status_code == 200
    assert [case["id"] for case in response.json()] == [owned["id"]]
    assert response.json()[0]["owner_id"] == "owner-a"
    assert oversized.status_code == 422
    direct = client.get(f"/v1/cases/{owned['id']}", headers=_headers())
    cross_owner = client.get(
        f"/v1/cases/{owned['id']}", headers=_headers("owner-b-token")
    )
    assert direct.status_code == 200
    assert direct.json()["id"] == owned["id"]
    assert cross_owner.status_code == 404


def test_case_scan_history_is_newest_first_and_owner_scoped() -> None:
    client, _, _ = _client()
    case = _create_case(client)
    first = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "one.example"}]},
        headers=_headers(),
    ).json()
    second = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "two.example"}]},
        headers=_headers(),
    ).json()

    response = client.get(
        f"/v1/cases/{case['id']}/scans", headers=_headers()
    )
    first_page = client.get(
        f"/v1/cases/{case['id']}/scans?limit=1", headers=_headers()
    )
    second_page = client.get(
        f"/v1/cases/{case['id']}/scans?offset=1&limit=1", headers=_headers()
    )
    forbidden = client.get(
        f"/v1/cases/{case['id']}/scans", headers=_headers("owner-b-token")
    )
    oversized = client.get(
        f"/v1/cases/{case['id']}/scans?limit=101", headers=_headers()
    )

    assert response.status_code == 200
    assert [scan["id"] for scan in response.json()] == [second["id"], first["id"]]
    assert [scan["id"] for scan in first_page.json()] == [second["id"]]
    assert [scan["id"] for scan in second_page.json()] == [first["id"]]
    assert forbidden.status_code == 404
    assert oversized.status_code == 422


def test_create_status_and_cancel_scan_persists_and_aborts_queue_job() -> None:
    client, store, queue = _client()
    case = _create_case(client)

    created = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [
                {"target_type": "domain", "target_value": "example.com"}
            ]
        },
        headers=_headers(),
    )

    assert created.status_code == 202
    scan = created.json()
    assert scan["state"] == "queued"
    assert scan["job_id"].startswith("job_")
    status = client.get(f"/v1/scans/{scan['id']}", headers=_headers())
    assert status.status_code == 200
    assert status.json()["job_id"] == scan["job_id"]
    assert status.json()["adapter_runs"] == []
    adapter_run = AdapterRun(
        id="cancel-run",
        case_id=case["id"],
        scan_id=scan["id"],
        owner_id="owner-a",
        adapter_id="shodan",
        adapter_version="1",
        source_target=ScanTarget(
            target_type="domain", target_value="example.com"
        ),
        state=AdapterState.RUNNING,
    )
    asyncio.run(store.add_adapter_run(adapter_run))

    cancelled = client.post(
        f"/v1/scans/{scan['id']}/cancel", headers=_headers()
    )
    assert cancelled.status_code == 202
    assert cancelled.json()["state"] == "cancelled"
    assert cancelled.json()["adapter_runs"][0]["id"] == "cancel-run"
    assert cancelled.json()["adapter_runs"][0]["state"] == "failed"
    assert cancelled.json()["adapter_runs"][0]["outcome_code"] == "cancelled"
    assert scan["job_id"] in queue.aborted_job_ids


def test_scan_creation_is_idempotent_for_retried_requests() -> None:
    client, _, queue = _client()
    case = _create_case(client)
    body = {
        "targets": [{"target_type": "domain", "target_value": "example.com"}]
    }
    headers = {**_headers(), "Idempotency-Key": "scan-request-123"}

    first = client.post(
        f"/v1/cases/{case['id']}/scans", json=body, headers=headers
    )
    second = client.post(
        f"/v1/cases/{case['id']}/scans", json=body, headers=headers
    )

    assert first.status_code == second.status_code == 202
    assert first.json()["id"] == second.json()["id"]
    assert len(queue.jobs) == 1
    assert "idempotency_hash" not in first.json()


def test_idempotent_retry_repairs_an_orphaned_queue_dispatch() -> None:
    client, _, queue = _client()
    case = _create_case(client)
    body = {"targets": [{"target_type": "domain", "target_value": "example.com"}]}
    headers = {**_headers(), "Idempotency-Key": "orphan-repair"}

    first = client.post(
        f"/v1/cases/{case['id']}/scans", json=body, headers=headers
    )
    queue.jobs.clear()
    second = client.post(
        f"/v1/cases/{case['id']}/scans", json=body, headers=headers
    )

    assert first.status_code == second.status_code == 202
    assert second.json()["job_id"] in queue.jobs
    assert queue.jobs[second.json()["job_id"]] == first.json()["id"]


def test_idempotency_key_cannot_be_reused_for_a_different_scan() -> None:
    client, _, _ = _client()
    case = _create_case(client)
    headers = {**_headers(), "Idempotency-Key": "scan-request-123"}
    first = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [{"target_type": "domain", "target_value": "example.com"}]
        },
        headers=headers,
    )
    second = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [{"target_type": "domain", "target_value": "other.example"}]
        },
        headers=headers,
    )

    assert first.status_code == 202
    assert second.status_code == 409


def test_cross_owner_scan_is_indistinguishable_from_missing() -> None:
    client, _, _ = _client()
    case = _create_case(client)
    created = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [
                {"target_type": "domain", "target_value": "example.com"}
            ]
        },
        headers=_headers(),
    ).json()

    status = client.get(
        f"/v1/scans/{created['id']}", headers=_headers("owner-b-token")
    )
    cancel = client.post(
        f"/v1/scans/{created['id']}/cancel",
        headers=_headers("owner-b-token"),
    )

    assert status.status_code == 404
    assert cancel.status_code == 404


@pytest.mark.parametrize(
    ("allow_active", "confirmed", "token", "expected"),
    [
        (False, True, "admin-token", 403),
        (True, False, "admin-token", 400),
        (True, True, "owner-a-token", 403),
        (True, True, "admin-token", 202),
    ],
)
def test_active_scan_policy(
    allow_active: bool, confirmed: bool, token: str, expected: int
) -> None:
    config = Settings(
        AUTH_ENABLED=True,
        ALLOW_ACTIVE_SCANNING=allow_active,
        ACTIVE_TARGET_ALLOWLIST=["domain:example.com"] if allow_active else [],
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        _env_file=None,
    )
    client, _, _ = _client(config=config)
    case = _create_case(client, token)

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [
                {"target_type": "domain", "target_value": "example.com"}
            ],
            "mode": "active",
            "active_scan_confirmed": confirmed,
        },
        headers=_headers(token),
    )

    assert response.status_code == expected


@pytest.mark.parametrize(
    ("target", "allowlist"),
    [
        ({"target_type": "domain", "target_value": "outside.example"}, ["domain:example.com"]),
        ({"target_type": "ip", "target_value": "127.0.0.1"}, ["ip:127.0.0.0/8"]),
    ],
)
def test_active_scan_targets_require_explicit_safe_scope(target, allowlist) -> None:
    config = Settings(
        AUTH_ENABLED=True,
        ALLOW_ACTIVE_SCANNING=True,
        ACTIVE_TARGET_ALLOWLIST=allowlist,
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        _env_file=None,
    )
    client, _, _ = _client(config=config)
    case = _create_case(client, "admin-token")

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [target],
            "mode": "active",
            "active_scan_confirmed": True,
        },
        headers=_headers("admin-token"),
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "targets",
    [
        [],
        [
            {"target_type": "domain", "target_value": "one.example"},
            {"target_type": "domain", "target_value": "two.example"},
        ],
        [{"target_type": "email", "target_value": "not-an-email"}],
        [{"target_type": "unknown", "target_value": "example.com"}],
        [{"target_type": "domain", "target_value": "   "}],
    ],
)
def test_batch_limit_and_target_validation(targets: list[dict[str, str]]) -> None:
    config = Settings(
        AUTH_ENABLED=True,
        MAX_BATCH_SIZE=1,
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        _env_file=None,
    )
    client, _, _ = _client(config=config)
    case = _create_case(client)

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": targets},
        headers=_headers(),
    )

    assert response.status_code == 422


def test_scan_targets_are_canonicalized_at_the_api_boundary() -> None:
    client, _, _ = _client()
    case = _create_case(client)

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [
                {"target_type": "domain", "target_value": "EXAMPLE.COM."}
            ]
        },
        headers=_headers(),
    )

    assert response.status_code == 202
    assert response.json()["targets"] == [
        {"target_type": "domain", "target_value": "example.com"}
    ]


def test_capabilities_resolve_shodan_credentials_without_exposing_them() -> None:
    without_client, _, _ = _client()
    with_client, _, _ = _client(
        config=Settings(
            AUTH_ENABLED=True,
            SHODAN_API_KEY="real-looking-test-key",
            OIDC_ISSUER="https://issuer.example.test/",
            OIDC_AUDIENCE="recon-api",
            OIDC_JWKS_URL="https://issuer.example.test/jwks",
            _env_file=None,
        )
    )

    without = without_client.get("/v1/capabilities", headers=_headers())
    with_key = with_client.get("/v1/capabilities", headers=_headers())

    assert without.status_code == 200
    assert with_key.status_code == 200
    unavailable = next(
        item for item in without.json()["adapters"] if item["adapter_id"] == "shodan"
    )
    available = next(
        item for item in with_key.json()["adapters"] if item["adapter_id"] == "shodan"
    )
    assert unavailable["enabled"] is False
    assert unavailable["unavailable_reason"] == "missing_credentials"
    assert available["enabled"] is True
    assert "real-looking-test-key" not in with_key.text


def test_capabilities_report_principal_active_authorization_and_scope() -> None:
    config = Settings(
        AUTH_ENABLED=True,
        ALLOW_ACTIVE_SCANNING=True,
        ACTIVE_TARGET_ALLOWLIST=["domain:example.com"],
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        _env_file=None,
    )
    client, _, _ = _client(config=config)

    analyst = client.get("/v1/capabilities", headers=_headers()).json()["policy"]
    admin = client.get(
        "/v1/capabilities", headers=_headers("admin-token")
    ).json()["policy"]

    assert analyst["active_scanning_enabled"] is True
    assert analyst["active_scope_configured"] is True
    assert analyst["active_scanning_authorized"] is False
    assert admin["active_scanning_authorized"] is True


def test_explicitly_selected_unavailable_adapter_is_rejected_before_queueing() -> None:
    client, _, queue = _client()
    case = _create_case(client)

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [{"target_type": "ip", "target_value": "203.0.113.10"}],
            "adapter_ids": ["shodan"],
        },
        headers=_headers(),
    )

    assert response.status_code == 422
    assert "unavailable" in response.json()["detail"]
    assert queue.jobs == {}


def test_graph_endpoint_is_owned_scan_scoped_and_paginated() -> None:
    client, store, _ = _client()
    case = _create_case(client)
    scan = Scan(
        id="scan-graph",
        case_id=case["id"],
        owner_id="owner-a",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        state=ScanState.SUCCEEDED,
    )
    node = GraphNode(
        id="node-1",
        case_id=case["id"],
        scan_id=scan.id,
        owner_id="owner-a",
        entity_type="domain",
        value="example.com",
    )
    provenance = Provenance(
        id="prov-1",
        case_id=case["id"],
        scan_id=scan.id,
        owner_id="owner-a",
        node_id=node.id,
        source_adapter_id="shodan",
        adapter_version="1",
        confidence=1,
        source_target=scan.targets[0],
        source_relationship="observed_from",
    )
    asyncio.run(store.create_scan(scan))
    asyncio.run(store.add_graph_records([node], [], [provenance]))

    response = client.get(
        f"/v1/scans/{scan.id}/graph?limit=1", headers=_headers()
    )

    assert response.status_code == 200
    assert response.json()["nodes"][0]["entity_type"] == "domain"
    assert response.json()["provenance"][0]["scan_id"] == scan.id
    assert client.get(
        f"/v1/scans/{scan.id}/graph", headers=_headers("owner-b-token")
    ).status_code == 404


def test_terminal_sse_event_closes_stream() -> None:
    client, store, _ = _client()
    case = _create_case(client)
    scan = Scan(
        id="scan-terminal",
        case_id=case["id"],
        owner_id="owner-a",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        state=ScanState.SUCCEEDED,
        outcome_code="complete",
    )
    asyncio.run(store.create_scan(scan))

    response = client.get(f"/v1/scans/{scan.id}/events", headers=_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "private, no-store"
    assert f"id: initial-{scan.id}" in response.text
    assert '"state":"succeeded"' in response.text
    resumed = client.get(
        f"/v1/scans/{scan.id}/events",
        headers={**_headers(), "Last-Event-ID": f"initial-{scan.id}"},
    )
    assert resumed.status_code == 200
    assert resumed.text == ""


def test_liveness_readiness_metrics_and_request_ids() -> None:
    client, _, _ = _client(queue=_UnhealthyQueue())

    live = client.get("/health/live", headers={"X-Request-ID": "request-test"})
    operations_headers = {"X-Operations-Token": "test-operations-token"}
    client.app.state.services.config.OPERATIONS_TOKEN = "test-operations-token"
    ready = client.get("/health/ready", headers=operations_headers)
    metrics = client.get("/metrics", headers=operations_headers)

    assert live.status_code == 200
    assert live.headers["X-Request-ID"] == "request-test"
    assert ready.status_code == 503
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "recon_http_requests_total" in metrics.text
    assert "recon_queue_depth" in metrics.text


def test_readiness_checks_rate_limiter_health() -> None:
    client, _, _ = _client(limiter=_UnhealthyRateLimiter(100, 60))
    operations_headers = {"X-Operations-Token": "test-operations-token"}

    response = client.get("/health/ready", headers=operations_headers)

    assert response.status_code == 503
    assert response.json()["rate_limiter"] is False


@pytest.mark.asyncio
async def test_production_store_initialization_recovers_after_startup_race() -> None:
    store = _RecoveringStore()
    services = ServiceContainer(
        config=Settings(AUTH_ENABLED=False, _env_file=None),
        store=store,
        queue=InMemoryScanQueue(),
        rate_limiter=InMemoryRateLimiter(100, 60),
    )

    await _repair_production_services(services)
    assert services.startup_errors == ("store:connectivity",)
    assert services.store_initialized is False

    await _repair_production_services(services)
    assert services.startup_errors == ()
    assert services.store_initialized is True
    assert store.initialize_calls == 1


def test_readiness_fails_when_enabled_authentication_is_not_configured() -> None:
    config = Settings(
        AUTH_ENABLED=True,
        OPERATIONS_TOKEN="test-operations-token",
        _env_file=None,
    )
    app = create_app(
        config,
        store=InMemoryStore(),
        queue=InMemoryScanQueue(),
        rate_limiter=InMemoryRateLimiter(100, 60),
    )
    client = TestClient(app)

    response = client.get(
        "/health/ready",
        headers={"X-Operations-Token": "test-operations-token"},
    )

    assert response.status_code == 503
    assert response.json()["auth"] is False


def test_store_failure_is_503_never_successful_empty_data() -> None:
    client, _, _ = _client(store=_FailingListStore())

    response = client.get("/v1/cases", headers=_headers())

    assert response.status_code == 503
    assert response.json()["detail"] == "service dependency unavailable"


def test_queue_failure_is_503_and_never_reports_a_queued_success() -> None:
    client, _, _ = _client(queue=_FailingQueue())
    case = _create_case(client)

    response = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={
            "targets": [
                {"target_type": "domain", "target_value": "example.com"}
            ]
        },
        headers=_headers(),
    )

    assert response.status_code == 503


def test_per_principal_rate_limit_is_enforced() -> None:
    client, _, _ = _client(limiter=InMemoryRateLimiter(1, 60))
    assert _create_case(client)["owner_id"] == "owner-a"

    limited = client.get("/v1/cases", headers=_headers())

    assert limited.status_code == 429


def test_invalid_tokens_are_bounded_before_repeated_verification() -> None:
    client, _, _ = _client(limiter=InMemoryRateLimiter(1, 60))

    first = client.get("/v1/cases", headers=_headers("invalid-one"))
    second = client.get("/v1/cases", headers=_headers("invalid-two"))

    assert first.status_code == 401
    assert second.status_code == 429


def test_oversized_authorization_header_is_rejected_before_verification() -> None:
    config = Settings(
        AUTH_ENABLED=True,
        MAX_AUTHORIZATION_HEADER_BYTES=256,
        OIDC_ISSUER="https://issuer.example.test/",
        OIDC_AUDIENCE="recon-api",
        OIDC_JWKS_URL="https://issuer.example.test/jwks",
        _env_file=None,
    )
    client, _, _ = _client(config=config)

    response = client.get(
        "/v1/cases", headers={"Authorization": f"Bearer {'x' * 300}"}
    )

    assert response.status_code == 431


def test_request_body_limit_runs_before_json_parsing() -> None:
    config = Settings(AUTH_ENABLED=False, MAX_REQUEST_BODY_BYTES=32, _env_file=None)
    client, _, _ = _client(config=config)

    response = client.post("/v1/cases", content=b"x" * 33)

    assert response.status_code == 413


def test_metrics_use_bounded_route_templates_and_operations_authentication() -> None:
    client, _, _ = _client()
    client.get("/random-one")
    client.get("/random-two")

    unauthenticated = client.get("/metrics")
    metrics = client.get(
        "/metrics", headers={"X-Operations-Token": "test-operations-token"}
    )

    assert unauthenticated.status_code == 401
    assert metrics.status_code == 200
    assert "random-one" not in metrics.text
    assert "random-two" not in metrics.text
    assert 'path="unmatched"' in metrics.text


def test_docs_are_disabled_by_default() -> None:
    client, _, _ = _client()
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_outstanding_scan_and_queue_depth_quotas_are_enforced() -> None:
    config = Settings(
        AUTH_ENABLED=False,
        MAX_OUTSTANDING_SCANS_PER_PRINCIPAL=1,
        MAX_QUEUE_DEPTH=1,
        _env_file=None,
    )
    client, _, _ = _client(config=config)
    case = client.post("/v1/cases", json={"name": "Quota case"}).json()
    first = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "one.example"}]},
    )
    second = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "two.example"}]},
    )

    assert first.status_code == 202
    assert second.status_code == 429


def test_pending_abort_remains_requested_until_worker_acknowledges() -> None:
    client, _, _ = _client(queue=_PendingAbortQueue())
    case = _create_case(client)
    scan = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "example.com"}]},
        headers=_headers(),
    ).json()

    response = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())

    assert response.status_code == 202
    assert response.json()["state"] == "queued"
    assert response.json()["cancel_requested"] is True
    assert response.json()["outcome_code"] == "cancellation_requested"


def test_abort_transport_failure_returns_truthful_durable_pending_state() -> None:
    client, _, _ = _client(queue=_FailingAbortQueue())
    case = _create_case(client)
    scan = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "example.com"}]},
        headers=_headers(),
    ).json()

    response = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())

    assert response.status_code == 202
    assert response.json()["cancel_requested"] is True
    assert response.json()["outcome_code"] == "cancellation_requested"


def test_cancel_refreshes_a_concurrent_worker_acknowledgement() -> None:
    store = InMemoryStore()
    client, _, _ = _client(
        store=store, queue=_ConcurrentCancellationQueue(store)
    )
    case = _create_case(client)
    scan = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "example.com"}]},
        headers=_headers(),
    ).json()

    response = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())

    assert response.status_code == 202
    assert response.json()["state"] == "cancelled"
    assert response.json()["outcome_code"] == "cancelled"


def test_repeated_cancellation_does_not_double_count_the_metric() -> None:
    client, _, _ = _client()
    case = _create_case(client)
    scan = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "example.com"}]},
        headers=_headers(),
    ).json()

    first = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())
    second = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())
    metrics = client.get(
        "/metrics", headers={"X-Operations-Token": "test-operations-token"}
    )

    assert first.json()["state"] == "cancelled"
    assert second.json()["state"] == "cancelled"
    assert "recon_scans_cancelled_total 1" in metrics.text


def test_cancellation_persistence_failure_is_not_reported_as_success() -> None:
    client, _, _ = _client(store=_FailingCancellationStore())
    case = _create_case(client)
    scan = client.post(
        f"/v1/cases/{case['id']}/scans",
        json={"targets": [{"target_type": "domain", "target_value": "example.com"}]},
        headers=_headers(),
    ).json()

    response = client.post(f"/v1/scans/{scan['id']}/cancel", headers=_headers())

    assert response.status_code == 503
    assert response.json()["detail"] == "service dependency unavailable"


def test_correlation_id_is_cors_allowed_echoed_and_exposed() -> None:
    client, _, _ = _client()
    correlation_id = "correlation-test"

    response = client.get(
        "/health/live", headers={"X-Correlation-ID": correlation_id}
    )
    preflight = client.options(
        "/health/live",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Correlation-ID",
        },
    )

    assert response.headers["X-Correlation-ID"] == correlation_id
    assert response.headers["X-Request-ID"] == correlation_id
    assert preflight.status_code == 200
    assert "x-correlation-id" in preflight.headers[
        "access-control-allow-headers"
    ].casefold()


def test_w3c_trace_context_is_propagated_with_a_new_server_span() -> None:
    client, _, _ = _client()
    trace_id = "1" * 32
    parent_span = "2" * 16

    response = client.get(
        "/health/live",
        headers={"traceparent": f"00-{trace_id}-{parent_span}-01"},
    )

    version, returned_trace, server_span, flags = response.headers[
        "traceparent"
    ].split("-")
    assert version == "00"
    assert returned_trace == trace_id
    assert server_span != parent_span
    assert len(server_span) == 16
    assert flags == "01"


def test_obsolete_global_endpoints_are_removed() -> None:
    client, _, _ = _client()

    assert client.post("/scan", json={}).status_code == 404
    assert client.get("/graph").status_code == 404


def test_openapi_describes_versioned_scan_graph_and_capability_responses() -> None:
    client, _, _ = _client()

    schema = client.app.openapi()

    assert schema["info"]["version"].startswith("1.")
    assert schema["paths"]["/v1/scans/{scan_id}"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["$ref"].endswith("/ScanDetail")
    assert schema["paths"]["/v1/scans/{scan_id}/graph"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]["$ref"].endswith("/GraphPage")
    assert schema["paths"]["/v1/capabilities"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["$ref"].endswith("/CapabilitiesResponse")
