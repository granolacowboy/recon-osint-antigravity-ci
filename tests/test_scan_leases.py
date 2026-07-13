from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.queueing import InMemoryScanQueue
from app.main import ServiceContainer, _dispatch_loop
from app.schemas.outcomes import AdapterState
from app.schemas.platform import (
    AdapterRun,
    Case,
    GraphNode,
    Scan,
    ScanState,
    ScanTarget,
    utc_now,
)
from app.storage.base import StoreError
from app.storage.memory import InMemoryStore
from app.worker import _maintain_scan_lease


def _running_scan(*, updated_seconds_ago: int = 30) -> Scan:
    return Scan(
        id="scan-lease",
        case_id="case-lease",
        owner_id="owner-lease",
        targets=[
            ScanTarget(target_type="domain", target_value="example.com")
        ],
        state=ScanState.RUNNING,
        job_id="job-original",
        worker_attempt=1,
        started_at=utc_now() - timedelta(seconds=updated_seconds_ago),
        updated_at=utc_now() - timedelta(seconds=updated_seconds_ago),
        outcome_code="running",
    )


async def _seed(store: InMemoryStore, scan: Scan) -> None:
    await store.create_case(
        Case(id=scan.case_id, owner_id=scan.owner_id, name="Lease test")
    )
    await store.create_scan(scan)


def _retryable_queued_scan() -> Scan:
    return Scan(
        id="scan-dispatch-race",
        case_id="case-dispatch-race",
        owner_id="owner-dispatch-race",
        targets=[
            ScanTarget(target_type="domain", target_value="example.com")
        ],
        state=ScanState.QUEUED,
        job_id="job-dispatch-race",
        outcome_code="queue_retryable_failure",
    )


class _CancellationDuringEnqueueQueue(InMemoryScanQueue):
    def __init__(
        self, store: InMemoryStore, stop: asyncio.Event
    ) -> None:
        super().__init__()
        self.store = store
        self.stop = stop

    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str:
        queued_job_id = await super().enqueue(
            scan_id, owner_id, case_id, job_id
        )
        await self.store.request_cancellation(owner_id, scan_id)
        self.stop.set()
        return queued_job_id


class _ClaimDuringEnqueueQueue(InMemoryScanQueue):
    def __init__(
        self, store: InMemoryStore, stop: asyncio.Event
    ) -> None:
        super().__init__()
        self.store = store
        self.stop = stop

    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str:
        queued_job_id = await super().enqueue(
            scan_id, owner_id, case_id, job_id
        )
        claimed = await self.store.claim_scan(
            owner_id, scan_id, worker_attempt=1
        )
        assert claimed is not None
        self.stop.set()
        return queued_job_id


def test_worker_lease_must_outlive_its_heartbeat() -> None:
    with pytest.raises(ValidationError, match="must be greater"):
        Settings(
            WORKER_LEASE_HEARTBEAT_SECONDS=10,
            RUNNING_SCAN_LEASE_SECONDS=10,
            _env_file=None,
        )


@pytest.mark.asyncio
async def test_store_heartbeat_and_recovery_use_compare_and_set_ownership() -> None:
    store = InMemoryStore()
    scan = _running_scan()
    await _seed(store, scan)
    cutoff = utc_now() - timedelta(seconds=5)

    assert await store.list_pending_scans(
        limit=10, stale_before=cutoff
    ) == [scan]
    assert await store.touch_scan_lease(
        scan.owner_id, scan.id, worker_attempt=2
    ) is False

    recovered = await store.recover_stale_scan(
        scan.owner_id,
        scan.id,
        stale_before=cutoff,
        job_id="job-recovered",
    )

    assert recovered is not None
    assert recovered.state is ScanState.QUEUED
    assert recovered.outcome_code == "worker_lease_expired"
    assert recovered.job_id == "job-recovered"
    assert recovered.worker_attempt == 1
    assert await store.touch_scan_lease(
        scan.owner_id, scan.id, worker_attempt=1
    ) is False

    claimed = await store.claim_scan(
        scan.owner_id, scan.id, worker_attempt=2
    )
    assert claimed is not None
    assert claimed.state is ScanState.RUNNING
    assert claimed.worker_attempt == 2

    stale_finish = await store.finish_scan(
        scan.owner_id,
        scan.id,
        worker_attempt=1,
        state=ScanState.SUCCEEDED,
        outcome_code="complete",
    )
    assert stale_finish == claimed


@pytest.mark.asyncio
async def test_stale_worker_cannot_overwrite_replacement_artifacts() -> None:
    store = InMemoryStore()
    scan = _running_scan(updated_seconds_ago=0).model_copy(
        update={"state": ScanState.QUEUED, "worker_attempt": 0}
    )
    await _seed(store, scan)
    assert await store.claim_scan(
        scan.owner_id, scan.id, worker_attempt=1
    ) is not None
    assert await store.claim_scan(
        scan.owner_id, scan.id, worker_attempt=2
    ) is not None

    replacement_run = AdapterRun(
        id="run-shared",
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        adapter_id="fixture",
        adapter_version="replacement",
        source_target=scan.targets[0],
        state=AdapterState.SUCCEEDED,
        outcome_code="complete",
    )
    await store.add_adapter_run(replacement_run, worker_attempt=2)
    with pytest.raises(StoreError, match="lease was lost"):
        await store.add_adapter_run(
            replacement_run.model_copy(
                update={"adapter_version": "stale", "outcome_code": "stale"}
            ),
            worker_attempt=1,
        )

    replacement_node = GraphNode(
        id="node-shared",
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        entity_type="domain",
        value="replacement.example",
    )
    await store.add_graph_records(
        [replacement_node], [], [], worker_attempt=2
    )
    with pytest.raises(StoreError, match="lease was lost"):
        await store.add_graph_records(
            [replacement_node.model_copy(update={"value": "stale.example"})],
            [],
            [],
            worker_attempt=1,
        )

    runs = await store.list_adapter_runs(scan.owner_id, scan.id)
    graph = await store.get_graph(scan.owner_id, scan.id, cursor=None, limit=10)
    assert [(run.adapter_version, run.outcome_code) for run in runs] == [
        ("replacement", "complete")
    ]
    assert graph is not None
    assert [node.value for node in graph.nodes] == ["replacement.example"]


@pytest.mark.asyncio
async def test_dispatch_loop_requeues_a_stale_running_scan() -> None:
    store = InMemoryStore()
    scan = _running_scan(updated_seconds_ago=20)
    await _seed(store, scan)
    queue = InMemoryScanQueue()
    config = Settings(
        AUTH_ENABLED=False,
        DISPATCH_SWEEP_SECONDS=0.01,
        WORKER_LEASE_HEARTBEAT_SECONDS=1,
        RUNNING_SCAN_LEASE_SECONDS=5,
        _env_file=None,
    )
    services = ServiceContainer(config=config, store=store, queue=queue)
    stop = asyncio.Event()
    task = asyncio.create_task(_dispatch_loop(services, stop))

    try:
        for _ in range(100):
            if queue.jobs:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("stale scan was not requeued")
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert persisted is not None
    assert persisted.state is ScanState.QUEUED
    assert persisted.outcome_code == "worker_lease_expired"
    assert persisted.job_id == "scan-lease-lease-2"
    assert queue.jobs == {"scan-lease-lease-2": scan.id}


@pytest.mark.asyncio
async def test_dispatch_loop_does_not_clear_concurrent_cancellation() -> None:
    store = InMemoryStore()
    scan = _retryable_queued_scan()
    await _seed(store, scan)
    stop = asyncio.Event()
    queue = _CancellationDuringEnqueueQueue(store, stop)
    services = ServiceContainer(
        config=Settings(AUTH_ENABLED=False, _env_file=None),
        store=store,
        queue=queue,
    )

    await asyncio.wait_for(_dispatch_loop(services, stop), timeout=1)

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert persisted is not None
    assert persisted.state is ScanState.QUEUED
    assert persisted.cancel_requested is True
    assert persisted.outcome_code == "cancellation_requested"


@pytest.mark.asyncio
async def test_dispatch_loop_does_not_roll_back_concurrent_worker_claim() -> None:
    store = InMemoryStore()
    scan = _retryable_queued_scan()
    await _seed(store, scan)
    stop = asyncio.Event()
    queue = _ClaimDuringEnqueueQueue(store, stop)
    services = ServiceContainer(
        config=Settings(AUTH_ENABLED=False, _env_file=None),
        store=store,
        queue=queue,
    )

    await asyncio.wait_for(_dispatch_loop(services, stop), timeout=1)

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert persisted is not None
    assert persisted.state is ScanState.RUNNING
    assert persisted.cancel_requested is False
    assert persisted.outcome_code == "running"
    assert persisted.worker_attempt == 1


@pytest.mark.asyncio
async def test_heartbeat_cancels_work_after_lease_loss() -> None:
    store = InMemoryStore()
    scan = _running_scan(updated_seconds_ago=0).model_copy(
        update={"state": ScanState.QUEUED}
    )
    await _seed(store, scan)
    owner_task = asyncio.create_task(asyncio.Event().wait())
    heartbeat = asyncio.create_task(
        _maintain_scan_lease(
            store,
            scan.owner_id,
            scan.id,
            worker_attempt=1,
            interval_seconds=0.01,
            owner_task=owner_task,
        )
    )

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(owner_task, timeout=1)
    await asyncio.wait_for(heartbeat, timeout=1)
