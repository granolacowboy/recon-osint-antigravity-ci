from __future__ import annotations

from app.engine.correlation import build_finding_records
from app.schemas.entities import DomainEntity
from app.schemas.platform import Scan, ScanTarget


def test_finding_records_use_canonical_types_and_complete_provenance() -> None:
    target = ScanTarget(target_type="ip", target_value="203.0.113.10")
    scan = Scan(
        id="scan-correlation",
        case_id="case-correlation",
        owner_id="owner-correlation",
        targets=[target],
    )

    records = build_finding_records(
        scan=scan,
        source_target=target,
        finding=DomainEntity(
            value="host.example.com", metadata={"confidence": 0.75}
        ),
        adapter_id="shodan",
        adapter_version="test-1.0",
    )

    assert [node.entity_type for node in records.nodes] == ["ip", "domain"]
    assert records.edges[0].source_node_id == records.nodes[0].id
    assert records.edges[0].target_node_id == records.nodes[1].id
    provenance = records.provenance[0]
    assert provenance.node_id == records.nodes[1].id
    assert provenance.source_adapter_id == "shodan"
    assert provenance.adapter_version == "test-1.0"
    assert provenance.scan_id == scan.id
    assert provenance.confidence == 0.75
    assert provenance.source_target == target
