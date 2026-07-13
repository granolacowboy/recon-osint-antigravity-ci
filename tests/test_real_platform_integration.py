from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from arq.connections import RedisSettings, create_pool
from arq.worker import Worker as ArqWorker

from app import worker
from app.adapters.ip import ShodanAdapter
from app.core.config import Settings
from app.core.queueing import ArqScanQueue
from app.core.rate_limit import InMemoryRateLimiter
from app.main import create_app
from app.schemas.platform import Case, Scan, ScanState, ScanTarget
from app.storage.neo4j import Neo4jStore


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_REAL_INTEGRATION") != "1",
    reason="set RUN_REAL_INTEGRATION=1 with Redis and Neo4j available",
)


async def _bounded(stage: str, awaitable, *, timeout: float = 10):
    """Fail the integration gate at the stalled component boundary."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except TimeoutError:
        raise AssertionError(
            f"real integration stage timed out: {stage} ({timeout:g}s)"
        ) from None


async def _wait_for_dependencies(config: Settings):
    redis = None
    store = Neo4jStore(config)
    try:
        deadline = asyncio.get_running_loop().time() + 12
        last_redis_error: Exception | None = None
        while asyncio.get_running_loop().time() < deadline:
            try:
                redis = await create_pool(
                    RedisSettings(
                        host=config.REDIS_HOST,
                        port=config.REDIS_PORT,
                        database=config.REDIS_DATABASE,
                        username=config.REDIS_USERNAME,
                        password=config.REDIS_PASSWORD,
                        ssl=config.REDIS_SSL,
                        conn_timeout=1,
                        conn_retries=0,
                    )
                )
                if await redis.ping():
                    break
                await redis.aclose()
                redis = None
            except Exception as exc:
                last_redis_error = exc
                if redis is not None:
                    await redis.aclose()
                    redis = None
            await asyncio.sleep(0.25)
        else:
            detail = (
                type(last_redis_error).__name__
                if last_redis_error
                else "unhealthy"
            )
            raise AssertionError(
                f"integration Redis did not become ready ({detail})"
            )

        neo4j_deadline = asyncio.get_running_loop().time() + 12
        while asyncio.get_running_loop().time() < neo4j_deadline:
            if await store.health():
                await _bounded(
                    "initialize Neo4j schema", store.initialize(), timeout=8
                )
                return redis, store
            await asyncio.sleep(0.25)
        raise AssertionError("integration Neo4j did not become ready")
    except BaseException:
        if redis is not None:
            await redis.aclose()
        await store.close()
        raise


async def _run_one_job(redis, queue_name: str, context: dict) -> None:
    runner = ArqWorker(
        [worker.run_case_scan_task],
        queue_name=queue_name,
        redis_pool=redis,
        ctx=context,
        burst=True,
        handle_signals=False,
        max_jobs=1,
        max_tries=1,
        allow_abort_jobs=True,
        health_check_interval=1,
        log_results=False,
    )
    await _bounded("ARQ worker burst", runner.async_run(), timeout=20)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_neo4j_serializes_owner_quota_across_cases() -> None:
    suffix = uuid4().hex
    owner_id = f"quota-owner-{suffix}"
    config = Settings(
        REDIS_HOST=os.getenv("INTEGRATION_REDIS_HOST", "127.0.0.1"),
        REDIS_PORT=int(os.getenv("INTEGRATION_REDIS_PORT", "6379")),
        REDIS_PASSWORD=os.getenv("INTEGRATION_REDIS_PASSWORD") or None,
        NEO4J_URI=os.getenv("INTEGRATION_NEO4J_URI", "bolt://127.0.0.1:7687"),
        NEO4J_USER=os.getenv("INTEGRATION_NEO4J_USER", "neo4j"),
        NEO4J_PASSWORD=os.getenv("INTEGRATION_NEO4J_PASSWORD", "integration-password"),
        _env_file=None,
    )
    redis, store = await _bounded(
        "quota dependency readiness", _wait_for_dependencies(config), timeout=30
    )
    cases = [
        Case(
            id=f"quota-case-{index}-{suffix}",
            owner_id=owner_id,
            name=f"Quota {index}",
        )
        for index in range(2)
    ]
    scans = [
        Scan(
            id=f"quota-scan-{index}-{suffix}",
            case_id=case.id,
            owner_id=owner_id,
            targets=[
                ScanTarget(
                    target_type="domain", target_value=f"{index}.example.test"
                )
            ],
        )
        for index, case in enumerate(cases)
    ]

    try:
        await asyncio.gather(*(store.create_case(case) for case in cases))
        admitted = await asyncio.gather(
            *(store.create_scan(scan, max_active=1) for scan in scans)
        )

        assert sum(result is not None for result in admitted) == 1
        assert await store.count_active_scans(owner_id) == 1
    finally:
        await redis.aclose()
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_api_arq_worker_neo4j_success_cancellation_and_isolation(
    monkeypatch,
) -> None:
    suffix = uuid4().hex
    queue_name = f"arq:integration:{suffix}"
    config = Settings(
        AUTH_ENABLED=False,
        LOCAL_PRINCIPAL_SUB=f"integration-owner-{suffix}",
        SHODAN_API_KEY="recorded-fixture-key",
        REDIS_HOST=os.getenv("INTEGRATION_REDIS_HOST", "127.0.0.1"),
        REDIS_PORT=int(os.getenv("INTEGRATION_REDIS_PORT", "6379")),
        REDIS_PASSWORD=os.getenv("INTEGRATION_REDIS_PASSWORD") or None,
        NEO4J_URI=os.getenv("INTEGRATION_NEO4J_URI", "bolt://127.0.0.1:7687"),
        NEO4J_USER=os.getenv("INTEGRATION_NEO4J_USER", "neo4j"),
        NEO4J_PASSWORD=os.getenv("INTEGRATION_NEO4J_PASSWORD", "integration-password"),
        _env_file=None,
    )
    redis, store = await _bounded(
        "dependency readiness", _wait_for_dependencies(config), timeout=30
    )
    queue = ArqScanQueue(
        redis, owns_pool=False, queue_name=queue_name
    )
    application = create_app(
        config,
        store=store,
        queue=queue,
        rate_limiter=InMemoryRateLimiter(1000, 60),
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://integration.test",
    )

    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "shodan_host.json").read_text(
            encoding="utf-8"
        )
    )

    async def recorded_provider(self, target):
        return fixture

    monkeypatch.setattr(ShodanAdapter, "run", recorded_provider)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    runner_task: asyncio.Task | None = None
    try:
        case_response = await _bounded(
            "create case",
            client.post("/v1/cases", json={"name": "Real integration"}),
        )
        case = case_response.json()
        created = await _bounded(
            "enqueue success scan",
            client.post(
                f"/v1/cases/{case['id']}/scans",
                json={
                    "targets": [
                        {"target_type": "ip", "target_value": "203.0.113.10"}
                    ],
                    "adapter_ids": ["shodan"],
                },
                headers={"Idempotency-Key": f"success-{suffix}"},
            ),
        )
        assert created.status_code == 202
        scan = created.json()

        await _bounded(
            "process success scan",
            _run_one_job(
                redis,
                queue_name,
                {"store": store, "settings": config},
            ),
            timeout=25,
        )
        status_response = await _bounded(
            "read success status", client.get(f"/v1/scans/{scan['id']}")
        )
        graph_response = await _bounded(
            "read success graph", client.get(f"/v1/scans/{scan['id']}/graph")
        )
        assert status_response.status_code == graph_response.status_code == 200
        status_payload = status_response.json()
        graph_payload = graph_response.json()
        assert status_payload["state"] == "succeeded"
        assert status_payload["adapter_runs"][0]["state"] == "succeeded"
        assert {node["entity_type"] for node in graph_payload["nodes"]} == {
            "ip",
            "domain",
        }
        assert graph_payload["provenance"][0]["source_adapter_id"] == "shodan"

        other_config = config.model_copy(
            update={"LOCAL_PRINCIPAL_SUB": f"other-owner-{suffix}"}
        )
        other_app = create_app(
            other_config,
            store=store,
            queue=queue,
            rate_limiter=InMemoryRateLimiter(1000, 60),
        )
        other_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=other_app),
            base_url="http://integration.test",
        )
        try:
            other_status = await _bounded(
                "cross-owner isolation",
                other_client.get(f"/v1/scans/{scan['id']}"),
            )
            assert other_status.status_code == 404
        finally:
            await _bounded(
                "close isolation client", other_client.aclose(), timeout=5
            )

        provider_started = asyncio.Event()

        async def slow_provider(self, target):
            provider_started.set()
            await asyncio.sleep(30)
            return fixture

        monkeypatch.setattr(ShodanAdapter, "run", slow_provider)
        cancellation = await _bounded(
            "enqueue cancellation scan",
            client.post(
                f"/v1/cases/{case['id']}/scans",
                json={
                    "targets": [
                        {"target_type": "ip", "target_value": "203.0.113.11"}
                    ],
                    "adapter_ids": ["shodan"],
                },
                headers={"Idempotency-Key": f"cancel-{suffix}"},
            ),
        )
        assert cancellation.status_code == 202
        cancelled_scan = cancellation.json()
        runner_task = asyncio.create_task(
            _run_one_job(
                redis,
                queue_name,
                {"store": store, "settings": config},
            )
        )
        await _bounded("wait for provider", provider_started.wait())
        cancelled = await _bounded(
            "request cancellation",
            client.post(f"/v1/scans/{cancelled_scan['id']}/cancel"),
        )
        assert cancelled.status_code == 202
        assert cancelled.json()["state"] == "cancelled"
        await _bounded("finish cancelled worker", runner_task, timeout=25)
        persisted = await _bounded(
            "read cancelled scan",
            store.get_scan(config.LOCAL_PRINCIPAL_SUB, cancelled_scan["id"]),
        )
        assert persisted is not None
        assert persisted.state is ScanState.CANCELLED
    finally:
        cleanup_errors: list[Exception] = []
        if runner_task is not None and not runner_task.done():
            runner_task.cancel()
            try:
                await _bounded(
                    "stop cancellation worker", runner_task, timeout=5
                )
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                cleanup_errors.append(exc)
        cleanup_steps = (
            ("close API client", client.aclose()),
            (
                "remove integration queue",
                redis.delete(queue_name, f"{queue_name}:health-check"),
            ),
            ("close Redis", redis.aclose()),
            ("close Neo4j", store.close()),
        )
        for stage, awaitable in cleanup_steps:
            try:
                await _bounded(stage, awaitable, timeout=5)
            except Exception as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise ExceptionGroup(
                "real integration cleanup failed", cleanup_errors
            )
