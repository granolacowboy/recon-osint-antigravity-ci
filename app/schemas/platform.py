from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.outcomes import AdapterState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class PlatformModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class ScanState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_SCAN_STATES = frozenset(
    {
        ScanState.SUCCEEDED,
        ScanState.PARTIAL,
        ScanState.FAILED,
        ScanState.CANCELLED,
    }
)


CanonicalEntityType = Literal[
    "username",
    "email",
    "phone",
    "domain",
    "ip",
    "url",
    "company",
    "vulnerability",
    "cve",
    "repository",
    "cloud_storage",
    "breach",
    "dark_web_forum",
]


class ScanTarget(PlatformModel):
    target_type: CanonicalEntityType
    target_value: str = Field(min_length=1, max_length=255)

    @field_validator("target_value")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("target_value must not be blank")
        return value


class Case(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("case"))
    owner_id: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Scan(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("scan"))
    case_id: str = Field(min_length=1)
    owner_id: str = Field(min_length=1)
    targets: list[ScanTarget] = Field(min_length=1)
    mode: ScanMode = ScanMode.PASSIVE
    adapter_ids: list[str] | None = None
    active_scan_confirmed: bool = False
    active_authorized_at: datetime | None = None
    active_authorized_by: str | None = None
    active_scope: list[str] = Field(default_factory=list)
    state: ScanState = ScanState.QUEUED
    job_id: str | None = None
    cancel_requested: bool = False
    worker_attempt: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    outcome_code: str | None = None
    idempotency_hash: str | None = Field(default=None, exclude=True, repr=False)


class AdapterRun(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("run"))
    case_id: str
    scan_id: str
    owner_id: str
    adapter_id: str
    adapter_version: str
    source_target: ScanTarget
    state: AdapterState
    attempts: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    outcome_code: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    latency_seconds: float = Field(default=0, ge=0)


class GraphNode(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("node"))
    case_id: str
    scan_id: str
    owner_id: str
    entity_type: CanonicalEntityType
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("edge"))
    case_id: str
    scan_id: str
    owner_id: str
    source_node_id: str
    target_node_id: str
    relationship: str = Field(min_length=1)


class Provenance(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("prov"))
    case_id: str
    scan_id: str
    owner_id: str
    node_id: str | None = None
    edge_id: str | None = None
    source_adapter_id: str
    adapter_version: str
    observed_at: datetime = Field(default_factory=utc_now)
    confidence: float = Field(ge=0, le=1)
    source_target: ScanTarget
    source_relationship: str = Field(min_length=1)


class ScanEvent(PlatformModel):
    id: str = Field(default_factory=lambda: new_id("event"))
    case_id: str
    scan_id: str
    owner_id: str
    state: ScanState
    outcome_code: str | None = None
    event_type: Literal["scan_status", "adapter_progress"] = "scan_status"
    adapter_id: str | None = None
    adapter_state: AdapterState | None = None
    created_at: datetime = Field(default_factory=utc_now)


class GraphPage(PlatformModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)
    next_cursor: str | None = None
