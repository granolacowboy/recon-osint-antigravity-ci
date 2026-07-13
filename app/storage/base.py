from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import datetime

from app.schemas.platform import (
    AdapterRun,
    Case,
    GraphEdge,
    GraphNode,
    GraphPage,
    Provenance,
    Scan,
    ScanEvent,
    ScanState,
    utc_now,
)
from app.schemas.outcomes import AdapterState


class StoreError(RuntimeError):
    """Durable store operation failed."""


def decode_graph_cursor(cursor: str | None) -> tuple[int, int, int]:
    if cursor is None:
        return 0, 0, 0
    try:
        if ":" not in cursor:
            node_offset = int(cursor)
            offsets = (node_offset, 0, 0)
        else:
            parts = cursor.split(":")
            if len(parts) != 3:
                raise ValueError
            offsets = tuple(int(part) for part in parts)
    except (TypeError, ValueError) as exc:
        raise StoreError("graph cursor is invalid") from exc
    if any(offset < 0 for offset in offsets):
        raise StoreError("graph cursor is invalid")
    return offsets  # type: ignore[return-value]


def encode_graph_cursor(node_offset: int, edge_offset: int, provenance_offset: int) -> str:
    return f"{node_offset}:{edge_offset}:{provenance_offset}"


class Store(ABC):
    @abstractmethod
    async def health(self) -> bool: ...

    @abstractmethod
    async def create_case(self, record: Case) -> Case: ...

    @abstractmethod
    async def list_cases(
        self, owner_id: str, *, offset: int = 0, limit: int
    ) -> list[Case]: ...

    @abstractmethod
    async def get_case(self, owner_id: str, case_id: str) -> Case | None: ...

    @abstractmethod
    async def create_scan(
        self, record: Scan, *, max_active: int | None = None
    ) -> Scan | None: ...

    @abstractmethod
    async def get_scan(self, owner_id: str, scan_id: str) -> Scan | None: ...

    @abstractmethod
    async def list_case_scans(
        self, owner_id: str, case_id: str, *, offset: int = 0, limit: int
    ) -> list[Scan]: ...

    @abstractmethod
    async def get_scan_by_idempotency(
        self, owner_id: str, case_id: str, idempotency_hash: str
    ) -> Scan | None: ...

    @abstractmethod
    async def list_pending_scans(
        self, *, limit: int, stale_before: datetime | None = None
    ) -> list[Scan]: ...

    @abstractmethod
    async def count_active_scans(self, owner_id: str) -> int: ...

    @abstractmethod
    async def update_scan(self, record: Scan) -> Scan: ...

    @abstractmethod
    async def mark_scan_dispatched(
        self, owner_id: str, scan_id: str, *, job_id: str
    ) -> Scan | None: ...

    @abstractmethod
    async def claim_scan(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> Scan | None: ...

    @abstractmethod
    async def touch_scan_lease(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> bool: ...

    @abstractmethod
    async def recover_stale_scan(
        self,
        owner_id: str,
        scan_id: str,
        *,
        stale_before: datetime,
        job_id: str,
    ) -> Scan | None: ...

    @abstractmethod
    async def finish_scan(
        self,
        owner_id: str,
        scan_id: str,
        *,
        worker_attempt: int,
        state: "ScanState",
        outcome_code: str,
    ) -> Scan | None: ...

    @abstractmethod
    async def set_scan_job_id(
        self, owner_id: str, scan_id: str, job_id: str
    ) -> Scan: ...

    @abstractmethod
    async def request_cancellation(self, owner_id: str, scan_id: str) -> Scan | None: ...

    @abstractmethod
    async def acknowledge_cancellation(
        self, owner_id: str, scan_id: str
    ) -> Scan | None: ...

    @abstractmethod
    async def add_adapter_run(
        self, record: AdapterRun, *, worker_attempt: int | None = None
    ) -> AdapterRun: ...

    @abstractmethod
    async def list_adapter_runs(
        self, owner_id: str, scan_id: str
    ) -> list[AdapterRun]: ...

    @abstractmethod
    async def add_event(
        self, event: ScanEvent, *, worker_attempt: int | None = None
    ) -> ScanEvent: ...

    @abstractmethod
    async def list_events(self, owner_id: str, scan_id: str) -> list[ScanEvent] | None: ...

    @abstractmethod
    async def add_graph_records(
        self,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
        provenance: Sequence[Provenance],
        *,
        worker_attempt: int | None = None,
    ) -> None: ...

    @abstractmethod
    async def get_graph(
        self, owner_id: str, scan_id: str, *, cursor: str | None, limit: int
    ) -> GraphPage | None: ...

    @abstractmethod
    async def purge_expired(self, before: datetime) -> int: ...

    @abstractmethod
    async def close(self) -> None: ...


async def finalize_cancelled_adapter_runs(
    store: Store, owner_id: str, scan_id: str
) -> list[AdapterRun]:
    """Durably close queued/running adapter records for a cancelled scan."""
    runs = await store.list_adapter_runs(owner_id, scan_id)
    finalized: list[AdapterRun] = []
    for run in runs:
        if run.state not in {AdapterState.QUEUED, AdapterState.RUNNING}:
            finalized.append(run)
            continue
        updated = run.model_copy(
            update={
                "state": AdapterState.FAILED,
                "outcome_code": "cancelled",
                "finished_at": utc_now(),
            }
        )
        finalized.append(await store.add_adapter_run(updated))
    return finalized
