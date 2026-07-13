from __future__ import annotations

import asyncio

import pytest
from arq import Retry

from app import worker
from app.adapters.ip import ShodanAdapter
from app.core.config import Settings
from app.schemas.entities import DomainEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState
from app.schemas.platform import Case, Scan, ScanState, ScanTarget
from app.storage.memory import InMemoryStore


async def _seed_scan(
    store: InMemoryStore, *, targets: list[ScanTarget] | None = None
) -> Scan:
    case = Case(id="case-worker", owner_id="owner-worker", name="Worker case")
    scan = Scan(
        id="scan-worker",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=targets
        or [ScanTarget(target_type="ip", target_value="203.0.113.10")],
    )
    await store.create_case(case)
    await store.create_scan(scan)
    return scan


def _execution(
    state: AdapterState,
    *,
    adapter_id: str = "shodan",
    findings: tuple = (),
    code: str = "",
) -> worker.AdapterExecution:
    return worker.AdapterExecution(
        outcome=AdapterOutcome(
            adapter_id=adapter_id,
            state=state,
            findings=findings,
            attempts=1,
            code=code,
        ),
        adapter_version="test-1.0",
        latency_seconds=0.01,
    )


@pytest.mark.asyncio
async def test_case_scan_worker_persists_success_runs_findings_and_provenance() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [
            _execution(
                AdapterState.SUCCEEDED,
                findings=(
                    DomainEntity(
                        value="host.example.com", metadata={"confidence": 0.8}
                    ),
                ),
            )
        ]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    persisted = await store.get_scan(scan.owner_id, scan.id)
    runs = await store.list_adapter_runs(scan.owner_id, scan.id)
    graph = await store.get_graph(scan.owner_id, scan.id, cursor=None, limit=100)
    assert result["state"] == "succeeded"
    assert persisted.state is ScanState.SUCCEEDED
    assert runs[0].state is AdapterState.SUCCEEDED
    assert runs[0].adapter_version == "test-1.0"
    assert {node.entity_type for node in graph.nodes} == {"ip", "domain"}
    finding_node = next(
        node for node in graph.nodes if node.value == "host.example.com"
    )
    finding_provenance = next(
        item for item in graph.provenance if item.node_id == finding_node.id
    )
    assert finding_provenance.source_adapter_id == "shodan"
    assert finding_provenance.adapter_version == "test-1.0"
    assert finding_provenance.confidence == 0.8
    assert finding_provenance.scan_id == scan.id
    assert finding_provenance.source_target == scan.targets[0]


@pytest.mark.asyncio
async def test_case_scan_worker_treats_no_results_as_success() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [_execution(AdapterState.NO_RESULTS)]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "succeeded"
    assert result["outcome_code"] == "no_findings"
    assert (await store.list_adapter_runs(scan.owner_id, scan.id))[0].state is AdapterState.NO_RESULTS


@pytest.mark.asyncio
async def test_case_scan_worker_aggregates_mixed_adapter_outcomes_as_partial() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [
            _execution(AdapterState.NO_RESULTS, adapter_id="shodan"),
            _execution(AdapterState.FAILED, adapter_id="other", code="upstream_failed"),
        ]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "partial"
    assert result["outcome_code"] == "adapter_partial_failure"


@pytest.mark.asyncio
async def test_case_scan_worker_aggregates_all_failures_as_failed() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [_execution(AdapterState.FAILED, code="upstream_failed")]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "failed"
    assert result["outcome_code"] == "adapter_failure"


@pytest.mark.asyncio
async def test_case_scan_worker_honors_cancellation_between_targets() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(
        store,
        targets=[
            ScanTarget(target_type="ip", target_value="203.0.113.10"),
            ScanTarget(target_type="ip", target_value="203.0.113.11"),
        ],
    )
    calls: list[str] = []

    async def execute(current_scan, target, config):
        calls.append(target.target_value)
        await store.request_cancellation(current_scan.owner_id, current_scan.id)
        return [_execution(AdapterState.NO_RESULTS)]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "cancelled"
    assert calls == ["203.0.113.10"]


@pytest.mark.asyncio
async def test_case_scan_worker_marks_partially_uncovered_batches_partial() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(
        store,
        targets=[
            ScanTarget(target_type="ip", target_value="203.0.113.10"),
            ScanTarget(target_type="domain", target_value="example.com"),
        ],
    )

    async def execute(scan, target, config):
        return [_execution(AdapterState.NO_RESULTS)] if target.target_type == "ip" else []

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "partial"
    assert result["outcome_code"] == "incomplete_target_coverage"


@pytest.mark.asyncio
async def test_case_scan_worker_persists_terminal_failure_on_unexpected_exception() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        raise ValueError("sensitive provider detail")

    with pytest.raises(RuntimeError, match="case scan execution failed"):
        await worker.run_case_scan_task(
            {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
            scan.id,
            scan.owner_id,
            scan.case_id,
        )

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert persisted.state is ScanState.FAILED
    assert persisted.outcome_code == "worker_failure"


@pytest.mark.asyncio
async def test_case_scan_worker_last_arq_attempt_persists_failure() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)
    config = Settings(WORKER_MAX_TRIES=2, _env_file=None)

    async def execute(scan, target, config):
        raise ValueError("provider remains unavailable")

    with pytest.raises(RuntimeError, match="case scan execution failed"):
        await worker.run_case_scan_task(
            {
                "store": store,
                "settings": config,
                "adapter_executor": execute,
                "job_try": config.WORKER_MAX_TRIES,
            },
            scan.id,
            scan.owner_id,
            scan.case_id,
        )

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert persisted.state is ScanState.FAILED
    assert persisted.outcome_code == "worker_failure"
    assert persisted.worker_attempt == config.WORKER_MAX_TRIES


@pytest.mark.asyncio
async def test_case_scan_worker_retry_claims_a_new_attempt_without_duplicate_runs() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)
    calls = 0

    async def execute(scan, target, config):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        return [_execution(AdapterState.NO_RESULTS)]

    context = {
        "store": store,
        "settings": Settings(_env_file=None),
        "adapter_executor": execute,
        "job_try": 1,
    }
    with pytest.raises(Retry):
        await worker.run_case_scan_task(
            context, scan.id, scan.owner_id, scan.case_id
        )
    retryable = await store.get_scan(scan.owner_id, scan.id)
    assert retryable.state is ScanState.RUNNING
    assert retryable.outcome_code == "retryable_worker_failure"

    context["job_try"] = 2
    result = await worker.run_case_scan_task(
        context, scan.id, scan.owner_id, scan.case_id
    )

    assert result["state"] == "succeeded"
    assert calls == 2
    assert len(await store.list_adapter_runs(scan.owner_id, scan.id)) == 1


class _FailSecondGraphWriteOnceStore(InMemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.graph_write_calls = 0
        self.failed = False

    async def add_graph_records(
        self, nodes, edges, provenance, *, worker_attempt=None
    ):
        self.graph_write_calls += 1
        if self.graph_write_calls == 2 and not self.failed:
            self.failed = True
            raise RuntimeError("transient graph write failure")
        return await super().add_graph_records(
            nodes, edges, provenance, worker_attempt=worker_attempt
        )


@pytest.mark.asyncio
async def test_graph_write_failure_retries_before_terminal_adapter_run() -> None:
    store = _FailSecondGraphWriteOnceStore()
    scan = await _seed_scan(store)
    executor_calls = 0

    async def execute(scan, target, config):
        nonlocal executor_calls
        executor_calls += 1
        return [
            _execution(
                AdapterState.SUCCEEDED,
                findings=(
                    DomainEntity(value="one.example.com"),
                    DomainEntity(value="two.example.com"),
                ),
            )
        ]

    context = {
        "store": store,
        "settings": Settings(_env_file=None),
        "adapter_executor": execute,
        "job_try": 1,
    }
    with pytest.raises(Retry):
        await worker.run_case_scan_task(
            context, scan.id, scan.owner_id, scan.case_id
        )

    assert await store.list_adapter_runs(scan.owner_id, scan.id) == []
    retryable = await store.get_scan(scan.owner_id, scan.id)
    assert retryable.state is ScanState.RUNNING
    assert retryable.outcome_code == "retryable_worker_failure"

    context["job_try"] = 2
    result = await worker.run_case_scan_task(
        context, scan.id, scan.owner_id, scan.case_id
    )
    graph = await store.get_graph(
        scan.owner_id, scan.id, cursor=None, limit=100
    )
    runs = await store.list_adapter_runs(scan.owner_id, scan.id)

    assert result["state"] == "succeeded"
    assert executor_calls == 2
    assert len(runs) == 1
    assert runs[0].state is AdapterState.SUCCEEDED
    assert {node.value for node in graph.nodes} == {
        "203.0.113.10",
        "one.example.com",
        "two.example.com",
    }
    assert len(graph.provenance) == 2


class _CancelAfterFirstGraphWriteStore(InMemoryStore):
    async def add_graph_records(
        self, nodes, edges, provenance, *, worker_attempt=None
    ):
        result = await super().add_graph_records(
            nodes, edges, provenance, worker_attempt=worker_attempt
        )
        await self.request_cancellation("owner-worker", "scan-worker")
        return result


@pytest.mark.asyncio
async def test_cancellation_during_finding_writes_stops_before_terminal_run() -> None:
    store = _CancelAfterFirstGraphWriteStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [
            _execution(
                AdapterState.SUCCEEDED,
                findings=(
                    DomainEntity(value="one.example.com"),
                    DomainEntity(value="two.example.com"),
                ),
            )
        ]

    result = await worker.run_case_scan_task(
        {
            "store": store,
            "settings": Settings(_env_file=None),
            "adapter_executor": execute,
        },
        scan.id,
        scan.owner_id,
        scan.case_id,
    )
    graph = await store.get_graph(
        scan.owner_id, scan.id, cursor=None, limit=100
    )

    assert result["state"] == "cancelled"
    assert await store.list_adapter_runs(scan.owner_id, scan.id) == []
    assert {node.value for node in graph.nodes} == {
        "203.0.113.10",
        "one.example.com",
    }


@pytest.mark.asyncio
async def test_user_cancelled_adapter_task_is_durably_acknowledged() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def execute(current_scan, target, config):
        await store.request_cancellation(
            current_scan.owner_id, current_scan.id
        )
        raise asyncio.CancelledError

    result = await worker.run_case_scan_task(
        {
            "store": store,
            "settings": Settings(_env_file=None),
            "adapter_executor": execute,
        },
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    persisted = await store.get_scan(scan.owner_id, scan.id)
    assert result["state"] == "cancelled"
    assert persisted.state is ScanState.CANCELLED
    assert persisted.outcome_code == "cancelled"
    assert await store.list_adapter_runs(scan.owner_id, scan.id) == []


@pytest.mark.asyncio
async def test_case_scan_worker_terminal_redelivery_is_a_noop() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)
    calls = 0

    async def execute(scan, target, config):
        nonlocal calls
        calls += 1
        return [_execution(AdapterState.NO_RESULTS)]

    context = {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute}
    first = await worker.run_case_scan_task(
        context, scan.id, scan.owner_id, scan.case_id
    )
    second = await worker.run_case_scan_task(
        context, scan.id, scan.owner_id, scan.case_id
    )

    assert first == second
    assert calls == 1
    assert len(await store.list_adapter_runs(scan.owner_id, scan.id)) == 1


def test_worker_never_executes_an_explicitly_requested_disabled_adapter() -> None:
    scan = Scan(
        id="scan-disabled",
        case_id="case-disabled",
        owner_id="owner-disabled",
        targets=[
            ScanTarget(target_type="username", target_value="alice")
        ],
        adapter_ids=["sherlock"],
    )

    registrations = worker._eligible_case_registrations(
        scan, scan.targets[0], Settings(_env_file=None)
    )

    assert registrations == []


@pytest.mark.asyncio
async def test_case_scan_worker_duplicate_delivery_does_not_steal_live_lease() -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def execute(scan, target, config):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return [_execution(AdapterState.NO_RESULTS)]

    context = {
        "store": store,
        "settings": Settings(_env_file=None),
        "adapter_executor": execute,
        "job_try": 1,
    }
    first = asyncio.create_task(
        worker.run_case_scan_task(
            context, scan.id, scan.owner_id, scan.case_id
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)

    duplicate = await worker.run_case_scan_task(
        context, scan.id, scan.owner_id, scan.case_id
    )
    assert duplicate["state"] == "running"
    assert calls == 1

    release.set()
    completed = await asyncio.wait_for(first, timeout=1)
    assert completed["state"] == "succeeded"


class _CancellationRaceStore(InMemoryStore):
    async def finish_scan(self, owner_id, scan_id, **kwargs):
        await self.request_cancellation(owner_id, scan_id)
        return await super().finish_scan(owner_id, scan_id, **kwargs)


@pytest.mark.asyncio
async def test_case_scan_worker_does_not_overwrite_last_moment_cancellation() -> None:
    store = _CancellationRaceStore()
    scan = await _seed_scan(store)

    async def execute(scan, target, config):
        return [_execution(AdapterState.NO_RESULTS)]

    result = await worker.run_case_scan_task(
        {"store": store, "settings": Settings(_env_file=None), "adapter_executor": execute},
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    assert result["state"] == "cancelled"
    assert (await store.get_scan(scan.owner_id, scan.id)).state is ScanState.CANCELLED


@pytest.mark.asyncio
async def test_case_scan_worker_persists_and_streams_adapter_progress(
    monkeypatch,
) -> None:
    store = InMemoryStore()
    scan = await _seed_scan(store)

    async def provider(self, target):
        return {"hostnames": ["host.example.com"], "ports": [443], "org": "Fixture"}

    monkeypatch.setattr(ShodanAdapter, "run", provider)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)
    result = await worker.run_case_scan_task(
        {
            "store": store,
            "settings": Settings(SHODAN_API_KEY="fixture-key", _env_file=None),
        },
        scan.id,
        scan.owner_id,
        scan.case_id,
    )

    runs = await store.list_adapter_runs(scan.owner_id, scan.id)
    events = await store.list_events(scan.owner_id, scan.id)
    progress = [event for event in events if event.event_type == "adapter_progress"]
    assert result["state"] == "succeeded"
    assert len(runs) == 1
    assert runs[0].state is AdapterState.SUCCEEDED
    assert runs[0].started_at is not None
    assert runs[0].finished_at is not None
    assert [event.adapter_state for event in progress] == [
        AdapterState.QUEUED,
        AdapterState.RUNNING,
        AdapterState.SUCCEEDED,
    ]
