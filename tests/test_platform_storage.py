from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.schemas.platform import (
    AdapterRun,
    Case,
    GraphEdge,
    GraphNode,
    Provenance,
    Scan,
    ScanMode,
    ScanState,
    ScanTarget,
)
from app.schemas.outcomes import AdapterState
from app.storage.memory import InMemoryStore
from app.schemas.platform import utc_now


@pytest.mark.asyncio
async def test_memory_store_persists_owned_cases_scans_and_queue_job_id() -> None:
    store = InMemoryStore()
    case = Case(id="case-1", owner_id="owner-a", name="Acme inquiry")
    scan = Scan(
        id="scan-1",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        mode=ScanMode.PASSIVE,
    )

    await store.create_case(case)
    await store.create_scan(scan)
    persisted = await store.set_scan_job_id("owner-a", scan.id, "job-123")

    assert await store.list_cases("owner-a", limit=50) == [case]
    assert await store.list_cases("owner-b", limit=50) == []
    assert await store.get_case("owner-b", case.id) is None
    assert await store.list_case_scans("owner-a", case.id, limit=50) == [persisted]
    assert await store.list_case_scans("owner-b", case.id, limit=50) == []
    assert persisted.job_id == "job-123"
    assert (await store.get_scan("owner-a", scan.id)).job_id == "job-123"
    assert await store.get_scan("owner-b", scan.id) is None


@pytest.mark.asyncio
async def test_memory_store_admits_owner_quota_atomically_across_cases() -> None:
    store = InMemoryStore()
    cases = [
        Case(id=f"case-quota-{index}", owner_id="owner-a", name=f"Quota {index}")
        for index in range(2)
    ]
    for case in cases:
        await store.create_case(case)
    scans = [
        Scan(
            id=f"scan-{index}",
            case_id=cases[index].id,
            owner_id=cases[index].owner_id,
            targets=[ScanTarget(target_type="domain", target_value=f"{index}.example")],
        )
        for index in range(2)
    ]

    results = await asyncio.gather(
        *(store.create_scan(scan, max_active=1) for scan in scans)
    )

    assert sum(result is not None for result in results) == 1
    assert await store.count_active_scans("owner-a") == 1


@pytest.mark.asyncio
async def test_memory_store_serializes_adapter_runs_and_cancellation() -> None:
    store = InMemoryStore()
    case = Case(id="case-1", owner_id="owner-a", name="Acme inquiry")
    scan = Scan(
        id="scan-1",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="ip", target_value="203.0.113.10")],
    )
    run = AdapterRun(
        id="run-1",
        case_id=case.id,
        scan_id=scan.id,
        owner_id=case.owner_id,
        adapter_id="shodan",
        adapter_version="1",
        source_target=scan.targets[0],
        state=AdapterState.NO_RESULTS,
    )

    await store.create_case(case)
    await store.create_scan(scan)
    await store.add_adapter_run(run)
    cancelled = await store.request_cancellation("owner-a", scan.id)

    assert cancelled.cancel_requested is True
    assert cancelled.state is ScanState.QUEUED
    assert cancelled.outcome_code == "cancellation_requested"
    cancelled = await store.acknowledge_cancellation("owner-a", scan.id)
    assert cancelled.state is ScanState.CANCELLED
    assert cancelled.outcome_code == "cancelled"
    assert await store.list_adapter_runs("owner-a", scan.id) == [run]


@pytest.mark.asyncio
async def test_graph_is_scan_scoped_canonical_provenanced_and_paginated() -> None:
    store = InMemoryStore()
    case = Case(id="case-1", owner_id="owner-a", name="Acme inquiry")
    scan = Scan(
        id="scan-1",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    await store.create_case(case)
    await store.create_scan(scan)
    nodes = [
        GraphNode(
            id="node-1",
            case_id=case.id,
            scan_id=scan.id,
            owner_id=case.owner_id,
            entity_type="domain",
            value="example.com",
        ),
        GraphNode(
            id="node-2",
            case_id=case.id,
            scan_id=scan.id,
            owner_id=case.owner_id,
            entity_type="ip",
            value="203.0.113.10",
        ),
    ]
    edge = GraphEdge(
        id="edge-1",
        case_id=case.id,
        scan_id=scan.id,
        owner_id=case.owner_id,
        source_node_id="node-1",
        target_node_id="node-2",
        relationship="resolves_to",
    )
    provenance = [
        Provenance(
            id=f"prov-{index}",
            case_id=case.id,
            scan_id=scan.id,
            owner_id=case.owner_id,
            node_id=node.id,
            source_adapter_id="shodan",
            adapter_version="1",
            confidence=0.9,
            source_target=scan.targets[0],
            source_relationship="observed_from",
        )
        for index, node in enumerate(nodes, start=1)
    ]
    await store.add_graph_records(nodes, [edge], provenance)

    first = await store.get_graph("owner-a", scan.id, cursor=None, limit=1)
    second = await store.get_graph(
        "owner-a", scan.id, cursor=first.next_cursor, limit=1
    )

    assert [node.entity_type for node in first.nodes + second.nodes] == [
        "domain",
        "ip",
    ]
    assert first.next_cursor == "1:1:1"
    assert second.next_cursor is None
    assert first.edges == [edge]
    assert second.edges == []
    assert first.edges + second.edges == [edge]
    complete = await store.get_graph("owner-a", scan.id, cursor=None, limit=2)
    assert complete.edges == [edge]
    assert first.provenance[0].source_adapter_id == "shodan"
    assert await store.get_graph("owner-b", scan.id, cursor=None, limit=100) is None


@pytest.mark.asyncio
async def test_memory_graph_persistence_upserts_deterministic_record_ids() -> None:
    store = InMemoryStore()
    case = Case(id="case-1", owner_id="owner-a", name="Acme inquiry")
    scan = Scan(
        id="scan-1",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    node = GraphNode(
        id="node-1",
        case_id=case.id,
        scan_id=scan.id,
        owner_id=case.owner_id,
        entity_type="domain",
        value="example.com",
    )
    provenance = Provenance(
        id="prov-1",
        case_id=case.id,
        scan_id=scan.id,
        owner_id=case.owner_id,
        node_id=node.id,
        source_adapter_id="shodan",
        adapter_version="shodan-host-api-v1",
        confidence=1,
        source_target=scan.targets[0],
        source_relationship="observed_from",
    )
    await store.create_case(case)
    await store.create_scan(scan)

    await store.add_graph_records([node], [], [provenance])
    await store.add_graph_records([node], [], [provenance])
    page = await store.get_graph("owner-a", scan.id, cursor=None, limit=100)

    assert [record.id for record in page.nodes] == ["node-1"]
    assert [record.id for record in page.provenance] == ["prov-1"]


def test_graph_nodes_reject_python_or_neo4j_class_labels() -> None:
    with pytest.raises(ValidationError):
        GraphNode(
            id="node-1",
            case_id="case-1",
            scan_id="scan-1",
            owner_id="owner-a",
            entity_type="DomainEntity",
            value="example.com",
        )


@pytest.mark.asyncio
async def test_retention_purge_removes_expired_scan_artifacts_but_keeps_case() -> None:
    store = InMemoryStore()
    case = Case(id="case-retention", owner_id="owner-a", name="Retention")
    scan = Scan(
        id="scan-expired",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
        created_at=utc_now() - timedelta(days=100),
    )
    await store.create_case(case)
    await store.create_scan(scan)

    deleted = await store.purge_expired(utc_now() - timedelta(days=90))

    assert deleted == 1
    assert await store.get_scan(case.owner_id, scan.id) is None
    assert await store.get_case(case.owner_id, case.id) == case


@pytest.mark.asyncio
async def test_memory_graph_upserts_canonical_records_by_id() -> None:
    store = InMemoryStore()
    case = Case(id="case-1", owner_id="owner-a", name="Canonical graph")
    scan = Scan(
        id="scan-1",
        case_id=case.id,
        owner_id=case.owner_id,
        targets=[ScanTarget(target_type="domain", target_value="example.com")],
    )
    node = GraphNode(
        id="node-canonical",
        case_id=case.id,
        scan_id=scan.id,
        owner_id=case.owner_id,
        entity_type="domain",
        value="example.com",
    )
    await store.create_case(case)
    await store.create_scan(scan)

    await store.add_graph_records([node], [], [])
    await store.add_graph_records([node], [], [])
    page = await store.get_graph("owner-a", scan.id, cursor=None, limit=100)

    assert page.nodes == [node]
