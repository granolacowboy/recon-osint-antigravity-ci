from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from app.adapters.registry import TARGET_MODEL_REGISTRY
from app.schemas.base import TargetEntity
from app.schemas.platform import (
    GraphEdge,
    GraphNode,
    Provenance,
    Scan,
    ScanTarget,
)


_ENTITY_TYPES = {
    model: entity_type for entity_type, model in TARGET_MODEL_REGISTRY.items()
}


def canonical_entity_type(entity: TargetEntity) -> str:
    try:
        return _ENTITY_TYPES[type(entity)]
    except KeyError as exc:
        raise ValueError(
            f"unregistered entity model: {type(entity).__name__}"
        ) from exc


def _record_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


def _confidence(metadata: dict[str, Any]) -> float:
    try:
        value = float(metadata.get("confidence", 1.0))
    except (TypeError, ValueError):
        value = 1.0
    return min(1.0, max(0.0, value))


@dataclass(frozen=True)
class FindingRecords:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    provenance: tuple[Provenance, ...]


def build_finding_records(
    *,
    scan: Scan,
    source_target: ScanTarget,
    finding: TargetEntity,
    adapter_id: str,
    adapter_version: str,
) -> FindingRecords:
    """Build canonical scan-scoped graph and provenance for one finding."""
    finding_type = canonical_entity_type(finding)
    source_id = _record_id(
        "node",
        scan.owner_id,
        scan.case_id,
        scan.id,
        source_target.target_type,
        source_target.target_value,
    )
    finding_id = _record_id(
        "node",
        scan.owner_id,
        scan.case_id,
        scan.id,
        finding_type,
        finding.value,
    )
    source = GraphNode(
        id=source_id,
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        entity_type=source_target.target_type,
        value=source_target.target_value,
    )
    discovered = GraphNode(
        id=finding_id,
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        entity_type=finding_type,
        value=finding.value,
        metadata=finding.metadata,
    )
    edge = GraphEdge(
        id=_record_id("edge", scan.id, source_id, finding_id, "discovered"),
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        source_node_id=source_id,
        target_node_id=finding_id,
        relationship="discovered",
    )
    provenance = Provenance(
        id=_record_id("prov", scan.id, finding_id, adapter_id, source_id),
        case_id=scan.case_id,
        scan_id=scan.id,
        owner_id=scan.owner_id,
        node_id=finding_id,
        source_adapter_id=adapter_id,
        adapter_version=adapter_version,
        confidence=_confidence(finding.metadata),
        source_target=source_target,
        source_relationship="discovered_from",
    )
    nodes = (source,) if source.id == discovered.id else (source, discovered)
    return FindingRecords(nodes=nodes, edges=(edge,), provenance=(provenance,))


class CorrelationEngine:
    """Deprecated in-process compatibility graph used only by the legacy worker."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _node(entity: TargetEntity) -> dict[str, Any]:
        entity_type = canonical_entity_type(entity)
        node_id = _record_id("compat", entity_type, entity.value)
        return {
            "id": node_id,
            "type": entity_type,
            "value": entity.value,
            "metadata": entity.metadata,
        }

    def add_entity(
        self,
        entity: TargetEntity,
        source_entity: TargetEntity | None = None,
        relationship: str = "discovered",
    ) -> None:
        node = self._node(entity)
        self._nodes[node["id"]] = node
        if source_entity is not None:
            source = self._node(source_entity)
            self._nodes[source["id"]] = source
            edge_id = _record_id(
                "compat_edge", source["id"], node["id"], relationship.casefold()
            )
            self._edges[edge_id] = {
                "id": edge_id,
                "source": source["id"],
                "target": node["id"],
                "relationship": relationship.casefold(),
            }

    def add_entities(
        self,
        entities: list[TargetEntity],
        source_entity: TargetEntity | None = None,
        relationship: str = "discovered",
    ) -> None:
        for entity in entities:
            self.add_entity(entity, source_entity, relationship)

    def correlate(self) -> dict[str, Any]:
        return {
            "status": "success",
            "nodes": list(self._nodes.values()),
            "edges": list(self._edges.values()),
        }

    def close(self) -> None:
        return None
