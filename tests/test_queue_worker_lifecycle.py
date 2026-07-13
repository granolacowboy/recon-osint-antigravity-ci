from __future__ import annotations

from dataclasses import dataclass

import pytest

from app import worker
from app.adapters.ip import ShodanAdapter
from app.core.config import Settings
from app.core.queueing import ArqScanQueue
from app.storage.memory import InMemoryStore


@dataclass(frozen=True)
class _Job:
    job_id: str


class _Pool:
    def __init__(self) -> None:
        self.enqueued: tuple | None = None
        self.options: dict | None = None

    async def enqueue_job(self, *args, **kwargs):
        self.enqueued = args
        self.options = kwargs
        return _Job("job-queue-test")


class _CompletedResultPool(_Pool):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0
        self.deleted: list[str] = []

    async def enqueue_job(self, *args, **kwargs):
        self.calls += 1
        self.enqueued = args
        self.options = kwargs
        return None if self.calls == 1 else _Job("job-queue-test")

    async def exists(self, key):
        return int(key.startswith("arq:result:"))

    async def delete(self, key):
        self.deleted.append(key)
        return 1


@pytest.mark.asyncio
async def test_arq_queue_passes_durable_scan_scope_to_worker() -> None:
    pool = _Pool()
    queue = ArqScanQueue(pool, owns_pool=False)

    job_id = await queue.enqueue(
        "scan-1", "owner-1", "case-1", "job-queue-test"
    )

    assert job_id == "job-queue-test"
    assert pool.enqueued == (
        "run_case_scan_task",
        "scan-1",
        "owner-1",
        "case-1",
    )
    assert pool.options == {
        "_job_id": "job-queue-test",
        "_queue_name": "arq:queue",
    }


@pytest.mark.asyncio
async def test_arq_queue_replaces_orphaned_completed_result_for_queued_scan() -> None:
    pool = _CompletedResultPool()
    queue = ArqScanQueue(pool, owns_pool=False)

    job_id = await queue.enqueue(
        "scan-1", "owner-1", "case-1", "job-queue-test"
    )

    assert job_id == "job-queue-test"
    assert pool.calls == 2
    assert pool.deleted == ["arq:result:job-queue-test"]


@pytest.mark.asyncio
async def test_worker_startup_verifies_store_and_shutdown_closes_it() -> None:
    store = InMemoryStore()
    config = Settings(_env_file=None)
    ctx = {
        "settings": config,
        "store_factory": lambda current_config: store,
    }

    await worker.startup_case_worker(ctx)

    assert ctx["store"] is store
    assert ctx["settings"] is config
    assert ctx["metrics"] is not None
    assert await store.health() is True

    await worker.shutdown_case_worker(ctx)
    assert await store.health() is False


def test_worker_settings_register_durable_lifecycle() -> None:
    assert worker.WorkerSettings.on_startup is worker.startup_case_worker
    assert worker.WorkerSettings.on_shutdown is worker.shutdown_case_worker
    assert worker.WorkerSettings.functions == [worker.run_case_scan_task]
    assert worker.run_scan_task not in worker.WorkerSettings.functions
    assert worker.WorkerSettings.allow_abort_jobs is True
    assert worker.WorkerSettings.log_results is False
    assert worker.WorkerSettings.health_check_interval <= 60
    assert worker.WorkerSettings.job_timeout >= 60


class _HealthPool:
    def __init__(self, *, heartbeat: bool) -> None:
        self.heartbeat = heartbeat

    async def ping(self):
        return True

    async def exists(self, key):
        return int(self.heartbeat and key.endswith(":health-check"))


@pytest.mark.asyncio
async def test_arq_queue_health_requires_a_worker_heartbeat() -> None:
    assert await ArqScanQueue(_HealthPool(heartbeat=True), owns_pool=False).health()
    assert not await ArqScanQueue(_HealthPool(heartbeat=False), owns_pool=False).health()


def test_enabled_shodan_adapter_has_explicit_provider_api_version() -> None:
    assert ShodanAdapter.version == "shodan-host-api-v1"
