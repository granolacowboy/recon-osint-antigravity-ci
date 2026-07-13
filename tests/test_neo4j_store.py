from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.schemas.outcomes import AdapterState
from app.schemas.platform import (
    AdapterRun,
    GraphEdge,
    GraphNode,
    Provenance,
    Scan,
    ScanState,
    ScanTarget,
    utc_now,
)
from app.storage.base import StoreError
from app.storage.neo4j import Neo4jStore


class _FakeAsyncDriver:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.connected = False
        self.closed = False
        self.responses: dict[str, list[dict]] = {}

    async def verify_connectivity(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

    async def execute_query(self, query, parameters_=None, **kwargs):
        parameters = parameters_ or {}
        self.calls.append((query, parameters))
        for marker, records in self.responses.items():
            if marker in query:
                return SimpleNamespace(records=records)
        return SimpleNamespace(records=[])


def _settings() -> Settings:
    return Settings(
        NEO4J_URI="bolt://neo4j.test:7687",
        NEO4J_USER="neo4j",
        NEO4J_PASSWORD="test-password",
        _env_file=None,
    )


@pytest.mark.asyncio
async def test_neo4j_store_verifies_connectivity_and_closes_driver() -> None:
    driver = _FakeAsyncDriver()
    store = Neo4jStore(_settings(), driver=driver)

    assert await store.health() is True
    await store.close()

    assert driver.connected is True
    assert driver.closed is True


@pytest.mark.asyncio
async def test_neo4j_store_initializes_uniqueness_constraints() -> None:
    driver = _FakeAsyncDriver()
    store = Neo4jStore(_settings(), driver=driver)

    await store.initialize()

    constraint_queries = [query for query, _ in driver.calls if "CONSTRAINT" in query]
    assert any("Scan" in query and "idempotency_hash" in query for query in constraint_queries)
    assert any("Case" in query and "id" in query for query in constraint_queries)
    assert any(
        "ScanAdmission" in query and "owner_id" in query
        for query in constraint_queries
    )


@pytest.mark.asyncio
async def test_neo4j_case_scan_history_is_owner_and_case_scoped() -> None:
    driver = _FakeAsyncDriver()
    scan = Scan(
        id="scan-1",
        case_id="case-1",
        owner_id="owner-1",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    driver.responses = {
        "MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]": [
            {"payload": scan.model_dump_json()}
        ]
    }
    store = Neo4jStore(_settings(), driver=driver)

    assert await store.list_case_scans("owner-1", "case-1", limit=50) == [scan]
    query, parameters = driver.calls[-1]
    assert "ORDER BY s.created_at DESC" in query
    assert parameters == {
        "owner_id": "owner-1",
        "case_id": "case-1",
        "offset": 0,
        "limit": 50,
    }


@pytest.mark.asyncio
async def test_neo4j_scan_admission_serializes_owner_quota_after_case_auth() -> None:
    driver = _FakeAsyncDriver()
    scan = Scan(
        id="scan-quota",
        case_id="case-quota",
        owner_id="owner-1",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    driver.responses = {
        "RETURN s.payload AS payload": [{"payload": scan.model_dump_json()}]
    }
    store = Neo4jStore(_settings(), driver=driver)

    assert await store.create_scan(scan, max_active=3) == scan
    query, parameters = driver.calls[-1]
    case_authorization = "MATCH (c:Case {id: $case_id, owner_id: $owner_id})"
    owner_lock = "MERGE (admission:ScanAdmission {owner_id: $owner_id})"
    assert case_authorization in query
    assert owner_lock in query
    assert query.index(case_authorization) < query.index(owner_lock)
    assert "SET admission.serial" in query
    assert "OPTIONAL MATCH (active:Scan {owner_id: $owner_id})" in query
    assert "OPTIONAL MATCH (c)-[:HAS_SCAN]->(active:Scan)" not in query
    assert "active.state IN ['queued', 'running']" in query
    assert parameters["max_active"] == 3


@pytest.mark.asyncio
async def test_neo4j_dispatch_acknowledgement_is_a_field_level_cas() -> None:
    driver = _FakeAsyncDriver()
    queued = Scan(
        id="scan-dispatch",
        case_id="case-dispatch",
        owner_id="owner-1",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        job_id="job-dispatch",
        outcome_code="queue_retryable_failure",
    )
    dispatched = queued.model_copy(update={"outcome_code": "queued"})
    driver.responses = {
        "MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->": [
            {"payload": queued.model_dump_json()}
        ],
        "s.outcome_code = 'queue_retryable_failure'": [
            {"payload": dispatched.model_dump_json()}
        ]
    }
    store = Neo4jStore(_settings(), driver=driver)

    result = await store.mark_scan_dispatched(
        queued.owner_id, queued.id, job_id=queued.job_id
    )

    assert result == dispatched
    query, parameters = driver.calls[-1]
    assert "s.state = 'queued'" in query
    assert "s.job_id = $job_id" in query
    assert "coalesce(s.cancel_requested, false) = false" in query
    assert "SET s.payload = $payload, s.outcome_code = 'queued'" in query
    assert "s.cancel_requested =" not in query
    assert "s.worker_attempt =" not in query
    assert parameters["job_id"] == queued.job_id


@pytest.mark.asyncio
async def test_neo4j_scan_lease_queries_are_cas_scoped() -> None:
    driver = _FakeAsyncDriver()
    stale_before = utc_now() - timedelta(seconds=60)
    running = Scan(
        id="scan-lease",
        case_id="case-lease",
        owner_id="owner-1",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        state=ScanState.RUNNING,
        job_id="job-original",
        worker_attempt=1,
        updated_at=stale_before - timedelta(seconds=1),
        outcome_code="running",
    )
    recovered = running.model_copy(
        update={
            "state": ScanState.QUEUED,
            "job_id": "job-recovered",
            "outcome_code": "worker_lease_expired",
            "updated_at": utc_now(),
        }
    )
    driver.responses = {
        "s.outcome_code = 'worker_lease_expired'": [
            {"payload": recovered.model_dump_json()}
        ],
        "RETURN count(s) AS touched": [{"touched": 1}],
        "RETURN s.payload AS payload": [
            {"payload": running.model_dump_json()}
        ],
    }
    store = Neo4jStore(_settings(), driver=driver)

    pending = await store.list_pending_scans(
        limit=10, stale_before=stale_before
    )
    assert pending == [running]
    pending_query, pending_parameters = driver.calls[-1]
    assert "datetime(s.updated_at) < datetime($stale_before)" in pending_query
    assert pending_parameters["stale_before"] == stale_before.isoformat()

    assert await store.touch_scan_lease(
        running.owner_id, running.id, worker_attempt=1
    ) is True
    touch_query, _ = driver.calls[-1]
    assert "coalesce(s.worker_attempt, 0) = $worker_attempt" in touch_query
    assert "coalesce(s.cancel_requested, false) = false" in touch_query

    result = await store.recover_stale_scan(
        running.owner_id,
        running.id,
        stale_before=stale_before,
        job_id="job-recovered",
    )
    assert result == recovered
    recovery_query, recovery_parameters = driver.calls[-1]
    assert "s.state = 'running'" in recovery_query
    assert "datetime(s.updated_at) < datetime($stale_before)" in recovery_query
    assert recovery_parameters["worker_attempt"] == 1


@pytest.mark.asyncio
async def test_neo4j_worker_artifacts_are_atomic_and_lease_scoped() -> None:
    driver = _FakeAsyncDriver()
    target = ScanTarget(target_type="domain", target_value="example.com")
    node = GraphNode(
        id="node-lease",
        case_id="case-lease",
        scan_id="scan-lease",
        owner_id="owner-1",
        entity_type="domain",
        value="example.com",
    )
    run = AdapterRun(
        id="run-lease",
        case_id=node.case_id,
        scan_id=node.scan_id,
        owner_id=node.owner_id,
        adapter_id="fixture",
        adapter_version="1",
        source_target=target,
        state=AdapterState.SUCCEEDED,
    )
    driver.responses = {
        "RETURN count(s) AS persisted": [{"persisted": 1}],
        "RETURN run.payload AS payload": [{"payload": run.model_dump_json()}],
    }
    store = Neo4jStore(_settings(), driver=driver)

    await store.add_graph_records([node], [], [], worker_attempt=2)
    graph_query, graph_parameters = driver.calls[-1]
    assert graph_query.count("MATCH (c:Case") == 1
    assert "s.state = 'running'" in graph_query
    assert "coalesce(s.worker_attempt, 0) = $worker_attempt" in graph_query
    assert "coalesce(s.cancel_requested, false) = false" in graph_query
    assert "FOREACH (item IN $nodes" in graph_query
    assert "FOREACH (item IN $edges" in graph_query
    assert "FOREACH (item IN $provenance" in graph_query
    assert graph_parameters["worker_attempt"] == 2

    assert await store.add_adapter_run(run, worker_attempt=2) == run
    run_query, run_parameters = driver.calls[-1]
    assert "s.state = 'running'" in run_query
    assert "coalesce(s.worker_attempt, 0) = $worker_attempt" in run_query
    assert run_parameters["worker_attempt"] == 2

    driver.responses = {}
    with pytest.raises(StoreError, match="lease was lost"):
        await store.add_graph_records([node], [], [], worker_attempt=1)


@pytest.mark.asyncio
async def test_neo4j_graph_query_is_owner_scan_scoped_and_paginated() -> None:
    driver = _FakeAsyncDriver()
    node = GraphNode(
        id="node-1",
        case_id="case-1",
        scan_id="scan-1",
        owner_id="owner-1",
        entity_type="domain",
        value="example.com",
    )
    edge = GraphEdge(
        id="edge-1",
        case_id="case-1",
        scan_id="scan-1",
        owner_id="owner-1",
        source_node_id="node-1",
        target_node_id="node-1",
        relationship="observed",
    )
    provenance = Provenance(
        id="prov-1",
        case_id="case-1",
        scan_id="scan-1",
        owner_id="owner-1",
        node_id="node-1",
        source_adapter_id="shodan",
        adapter_version="1",
        confidence=1,
        source_target=ScanTarget(
            target_type="domain", target_value="example.com"
        ),
        source_relationship="observed_from",
    )
    scan = Scan(
        id="scan-1",
        case_id="case-1",
        owner_id="owner-1",
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    driver.responses = {
        "RETURN s.payload AS payload": [{"payload": scan.model_dump_json()}],
        "RETURN n.payload AS payload": [{"payload": node.model_dump_json()}],
        "RETURN e.payload AS payload": [{"payload": edge.model_dump_json()}],
        "RETURN p.payload AS payload": [
            {"payload": provenance.model_dump_json()}
        ],
    }
    store = Neo4jStore(_settings(), driver=driver)

    page = await store.get_graph(
        "owner-1", "scan-1", cursor=None, limit=1
    )

    assert page.nodes == [node]
    assert page.edges == [edge]
    assert page.provenance == [provenance]
    assert page.next_cursor is None
    graph_calls = [call for call in driver.calls if "Graph" in call[0]]
    assert graph_calls
    assert all("owner_id" in query and "scan_id" in query for query, _ in graph_calls)
    assert all(params["owner_id"] == "owner-1" for _, params in graph_calls)
    assert all(params["scan_id"] == "scan-1" for _, params in graph_calls)


@pytest.mark.asyncio
async def test_neo4j_graph_pagination_rejects_oversized_or_invalid_cursor() -> None:
    store = Neo4jStore(_settings(), driver=_FakeAsyncDriver())

    with pytest.raises(StoreError):
        await store.get_graph("owner-1", "scan-1", cursor=None, limit=201)
    with pytest.raises(StoreError):
        await store.get_graph("owner-1", "scan-1", cursor="not-a-cursor", limit=100)
