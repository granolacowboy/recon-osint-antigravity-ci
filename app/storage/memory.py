from __future__ import annotations

import asyncio
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
    TERMINAL_SCAN_STATES,
    utc_now,
)
from app.storage.base import (
    Store,
    StoreError,
    decode_graph_cursor,
    encode_graph_cursor,
)


class InMemoryStore(Store):
    """Process-local store for deterministic tests and explicit local use."""

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._scans: dict[str, Scan] = {}
        self._adapter_runs: dict[str, list[AdapterRun]] = {}
        self._events: dict[str, list[ScanEvent]] = {}
        self._nodes: dict[str, list[GraphNode]] = {}
        self._edges: dict[str, list[GraphEdge]] = {}
        self._provenance: dict[str, list[Provenance]] = {}
        self._healthy = True
        self._lock = asyncio.Lock()

    async def health(self) -> bool:
        return self._healthy

    async def create_case(self, record: Case) -> Case:
        async with self._lock:
            if not self._healthy:
                raise StoreError("store is unavailable")
            self._cases[record.id] = record
            return record

    async def list_cases(
        self, owner_id: str, *, offset: int = 0, limit: int
    ) -> list[Case]:
        if not self._healthy:
            raise StoreError("store is unavailable")
        if offset < 0 or not 1 <= limit <= 100:
            raise StoreError("case history limit must be between 1 and 100")
        return sorted(
            (record for record in self._cases.values() if record.owner_id == owner_id),
            key=lambda record: (record.created_at, record.id),
            reverse=True,
        )[offset : offset + limit]

    async def get_case(self, owner_id: str, case_id: str) -> Case | None:
        if not self._healthy:
            raise StoreError("store is unavailable")
        record = self._cases.get(case_id)
        return record if record is not None and record.owner_id == owner_id else None

    async def create_scan(
        self, record: Scan, *, max_active: int | None = None
    ) -> Scan | None:
        async with self._lock:
            case = self._cases.get(record.case_id)
            if case is None or case.owner_id != record.owner_id:
                raise StoreError("owned case does not exist")
            if record.idempotency_hash is not None:
                existing = next(
                    (
                        item
                        for item in self._scans.values()
                        if item.owner_id == record.owner_id
                        and item.case_id == record.case_id
                        and item.idempotency_hash == record.idempotency_hash
                    ),
                    None,
                )
                if existing is not None:
                    return existing
            if max_active is not None:
                if max_active < 1:
                    raise StoreError("active scan quota must be positive")
                active_count = sum(
                    item.owner_id == record.owner_id
                    and item.state in {ScanState.QUEUED, ScanState.RUNNING}
                    for item in self._scans.values()
                )
                if active_count >= max_active:
                    return None
            self._scans[record.id] = record
            self._events.setdefault(record.id, []).append(
                ScanEvent(
                    id=f"initial-{record.id}",
                    case_id=record.case_id,
                    scan_id=record.id,
                    owner_id=record.owner_id,
                    state=record.state,
                    outcome_code=record.outcome_code,
                )
            )
            return record

    async def get_scan(self, owner_id: str, scan_id: str) -> Scan | None:
        if not self._healthy:
            raise StoreError("store is unavailable")
        record = self._scans.get(scan_id)
        return record if record is not None and record.owner_id == owner_id else None

    async def list_case_scans(
        self, owner_id: str, case_id: str, *, offset: int = 0, limit: int
    ) -> list[Scan]:
        if not self._healthy:
            raise StoreError("store is unavailable")
        if offset < 0 or not 1 <= limit <= 100:
            raise StoreError("case scan history limit must be between 1 and 100")
        return sorted(
            (
                record
                for record in self._scans.values()
                if record.owner_id == owner_id and record.case_id == case_id
            ),
            key=lambda record: (record.created_at, record.id),
            reverse=True,
        )[offset : offset + limit]

    async def get_scan_by_idempotency(
        self, owner_id: str, case_id: str, idempotency_hash: str
    ) -> Scan | None:
        if not self._healthy:
            raise StoreError("store is unavailable")
        return next(
            (
                record
                for record in self._scans.values()
                if record.owner_id == owner_id
                and record.case_id == case_id
                and record.idempotency_hash == idempotency_hash
            ),
            None,
        )

    async def list_pending_scans(
        self, *, limit: int, stale_before: datetime | None = None
    ) -> list[Scan]:
        if not self._healthy:
            raise StoreError("store is unavailable")
        if limit < 1:
            raise StoreError("pending scan limit must be positive")
        return sorted(
            (
                record
                for record in self._scans.values()
                if record.job_id
                and (
                    record.state is ScanState.QUEUED
                    or (
                        stale_before is not None
                        and record.state is ScanState.RUNNING
                        and record.updated_at < stale_before
                    )
                )
            ),
            key=lambda record: (record.created_at, record.id),
        )[:limit]

    async def count_active_scans(self, owner_id: str) -> int:
        if not self._healthy:
            raise StoreError("store is unavailable")
        return sum(
            record.owner_id == owner_id
            and record.state in {ScanState.QUEUED, ScanState.RUNNING}
            for record in self._scans.values()
        )

    async def update_scan(self, record: Scan) -> Scan:
        async with self._lock:
            current = self._scans.get(record.id)
            if current is None or current.owner_id != record.owner_id:
                raise StoreError("owned scan does not exist")
            updated = record.model_copy(update={"updated_at": utc_now()})
            self._scans[record.id] = updated
            if current.state != updated.state or current.outcome_code != updated.outcome_code:
                self._events.setdefault(record.id, []).append(
                    ScanEvent(
                        case_id=record.case_id,
                        scan_id=record.id,
                        owner_id=record.owner_id,
                        state=updated.state,
                        outcome_code=updated.outcome_code,
                    )
                )
            return updated

    async def mark_scan_dispatched(
        self, owner_id: str, scan_id: str, *, job_id: str
    ) -> Scan | None:
        """Clear a retryable dispatch outcome without replacing concurrent state."""
        async with self._lock:
            if not self._healthy:
                raise StoreError("store is unavailable")
            current = self._scans.get(scan_id)
            if (
                current is None
                or current.owner_id != owner_id
                or current.state is not ScanState.QUEUED
                or current.job_id != job_id
                or current.cancel_requested
                or current.outcome_code != "queue_retryable_failure"
            ):
                return None
            updated = current.model_copy(
                update={"outcome_code": "queued", "updated_at": utc_now()}
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def claim_scan(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> Scan | None:
        if worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        async with self._lock:
            current = self._scans.get(scan_id)
            if current is None or current.owner_id != owner_id:
                return None
            claimable = current.state is ScanState.QUEUED or (
                current.state is ScanState.RUNNING
                and worker_attempt > current.worker_attempt
            )
            if not claimable or current.cancel_requested:
                return None
            updated = current.model_copy(
                update={
                    "state": ScanState.RUNNING,
                    "started_at": current.started_at or utc_now(),
                    "updated_at": utc_now(),
                    "outcome_code": "running",
                    "worker_attempt": worker_attempt,
                }
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def touch_scan_lease(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> bool:
        if worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        async with self._lock:
            if not self._healthy:
                raise StoreError("store is unavailable")
            current = self._scans.get(scan_id)
            if (
                current is None
                or current.owner_id != owner_id
                or current.state is not ScanState.RUNNING
                or current.worker_attempt != worker_attempt
                or current.cancel_requested
            ):
                return False
            self._scans[scan_id] = current.model_copy(
                update={"updated_at": utc_now()}
            )
            return True

    async def recover_stale_scan(
        self,
        owner_id: str,
        scan_id: str,
        *,
        stale_before: datetime,
        job_id: str,
    ) -> Scan | None:
        if not job_id:
            raise StoreError("recovery job id must not be blank")
        async with self._lock:
            if not self._healthy:
                raise StoreError("store is unavailable")
            current = self._scans.get(scan_id)
            if (
                current is None
                or current.owner_id != owner_id
                or current.state is not ScanState.RUNNING
                or current.updated_at >= stale_before
                or current.cancel_requested
            ):
                return None
            updated = current.model_copy(
                update={
                    "state": ScanState.QUEUED,
                    "outcome_code": "worker_lease_expired",
                    "job_id": job_id,
                    "updated_at": utc_now(),
                }
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def finish_scan(
        self,
        owner_id: str,
        scan_id: str,
        *,
        worker_attempt: int,
        state: ScanState,
        outcome_code: str,
    ) -> Scan | None:
        async with self._lock:
            current = self._scans.get(scan_id)
            if current is None or current.owner_id != owner_id:
                return None
            if (
                current.state is not ScanState.RUNNING
                or current.worker_attempt != worker_attempt
                or current.cancel_requested
            ):
                return current
            finished_at = utc_now() if state in TERMINAL_SCAN_STATES else None
            updated = current.model_copy(
                update={
                    "state": state,
                    "outcome_code": outcome_code,
                    "finished_at": finished_at,
                    "updated_at": utc_now(),
                }
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def set_scan_job_id(
        self, owner_id: str, scan_id: str, job_id: str
    ) -> Scan:
        current = await self.get_scan(owner_id, scan_id)
        if current is None:
            raise StoreError("owned scan does not exist")
        return await self.update_scan(current.model_copy(update={"job_id": job_id}))

    async def request_cancellation(self, owner_id: str, scan_id: str) -> Scan | None:
        async with self._lock:
            current = self._scans.get(scan_id)
            if current is None or current.owner_id != owner_id:
                return None
            if current.state in TERMINAL_SCAN_STATES:
                return current
            updated = current.model_copy(
                update={
                    "cancel_requested": True,
                    "outcome_code": "cancellation_requested",
                    "updated_at": utc_now(),
                }
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def acknowledge_cancellation(
        self, owner_id: str, scan_id: str
    ) -> Scan | None:
        async with self._lock:
            current = self._scans.get(scan_id)
            if current is None or current.owner_id != owner_id:
                return None
            if current.state in TERMINAL_SCAN_STATES:
                return current
            if not current.cancel_requested:
                return current
            updated = current.model_copy(
                update={
                    "state": ScanState.CANCELLED,
                    "finished_at": utc_now(),
                    "outcome_code": "cancelled",
                    "updated_at": utc_now(),
                }
            )
            self._scans[scan_id] = updated
            self._append_event_if_changed(current, updated)
            return updated

    async def add_adapter_run(
        self, record: AdapterRun, *, worker_attempt: int | None = None
    ) -> AdapterRun:
        if worker_attempt is not None and worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        async with self._lock:
            scan = self._scans.get(record.scan_id)
            if (
                scan is None
                or scan.owner_id != record.owner_id
                or scan.case_id != record.case_id
            ):
                raise StoreError("owned scan does not exist")
            if worker_attempt is not None and (
                scan.state is not ScanState.RUNNING
                or scan.worker_attempt != worker_attempt
                or scan.cancel_requested
            ):
                raise StoreError("scan lease was lost before adapter run persistence")
            self._upsert(self._adapter_runs.setdefault(record.scan_id, []), [record])
        return record

    async def list_adapter_runs(
        self, owner_id: str, scan_id: str
    ) -> list[AdapterRun]:
        if await self.get_scan(owner_id, scan_id) is None:
            return []
        return list(self._adapter_runs.get(scan_id, ()))

    async def add_event(
        self, event: ScanEvent, *, worker_attempt: int | None = None
    ) -> ScanEvent:
        if worker_attempt is not None and worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        async with self._lock:
            scan = self._scans.get(event.scan_id)
            if scan is None or scan.owner_id != event.owner_id:
                raise StoreError("owned scan does not exist")
            if worker_attempt is not None and (
                scan.state is not ScanState.RUNNING
                or scan.worker_attempt != worker_attempt
                or scan.cancel_requested
            ):
                raise StoreError("scan lease was lost before event persistence")
            self._events.setdefault(event.scan_id, []).append(event)
            return event

    async def list_events(
        self, owner_id: str, scan_id: str
    ) -> list[ScanEvent] | None:
        if await self.get_scan(owner_id, scan_id) is None:
            return None
        return list(self._events.get(scan_id, ()))

    async def add_graph_records(
        self,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
        provenance: Sequence[Provenance],
        *,
        worker_attempt: int | None = None,
    ) -> None:
        if worker_attempt is not None and worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        records = [*nodes, *edges, *provenance]
        if not records:
            return
        scope = (records[0].owner_id, records[0].case_id, records[0].scan_id)
        if any(
            (record.owner_id, record.case_id, record.scan_id) != scope
            for record in records
        ):
            raise StoreError("graph records must share one owner/case/scan scope")
        owner_id, case_id, scan_id = scope
        async with self._lock:
            scan = self._scans.get(scan_id)
            if (
                scan is None
                or scan.owner_id != owner_id
                or scan.case_id != case_id
            ):
                raise StoreError("owned scan does not exist")
            if worker_attempt is not None and (
                scan.state is not ScanState.RUNNING
                or scan.worker_attempt != worker_attempt
                or scan.cancel_requested
            ):
                raise StoreError("scan lease was lost before graph persistence")
            self._upsert(self._nodes.setdefault(scan_id, []), nodes)
            self._upsert(self._edges.setdefault(scan_id, []), edges)
            self._upsert(
                self._provenance.setdefault(scan_id, []), provenance
            )

    @staticmethod
    def _upsert(existing: list, incoming: Sequence) -> None:
        positions = {record.id: index for index, record in enumerate(existing)}
        for record in incoming:
            index = positions.get(record.id)
            if index is None:
                positions[record.id] = len(existing)
                existing.append(record)
            else:
                existing[index] = record

    def _append_event_if_changed(self, current: Scan, updated: Scan) -> None:
        if current.state != updated.state or current.outcome_code != updated.outcome_code:
            self._events.setdefault(updated.id, []).append(
                ScanEvent(
                    case_id=updated.case_id,
                    scan_id=updated.id,
                    owner_id=updated.owner_id,
                    state=updated.state,
                    outcome_code=updated.outcome_code,
                )
            )

    async def get_graph(
        self, owner_id: str, scan_id: str, *, cursor: str | None, limit: int
    ) -> GraphPage | None:
        if await self.get_scan(owner_id, scan_id) is None:
            return None
        if not 1 <= limit <= 200:
            raise StoreError("graph limit must be between 1 and 200")
        node_offset, edge_offset, provenance_offset = decode_graph_cursor(cursor)
        nodes = sorted(self._nodes.get(scan_id, []), key=lambda record: record.id)
        edges = sorted(self._edges.get(scan_id, []), key=lambda record: record.id)
        provenance = sorted(
            self._provenance.get(scan_id, []), key=lambda record: record.id
        )
        page_nodes = nodes[node_offset : node_offset + limit]
        page_edges = edges[edge_offset : edge_offset + limit]
        page_provenance = provenance[
            provenance_offset : provenance_offset + limit
        ]
        next_node = node_offset + len(page_nodes)
        next_edge = edge_offset + len(page_edges)
        next_provenance = provenance_offset + len(page_provenance)
        has_more = (
            next_node < len(nodes)
            or next_edge < len(edges)
            or next_provenance < len(provenance)
        )
        return GraphPage(
            nodes=list(page_nodes),
            edges=list(page_edges),
            provenance=list(page_provenance),
            next_cursor=(
                encode_graph_cursor(next_node, next_edge, next_provenance)
                if has_more
                else None
            ),
        )

    async def purge_expired(self, before: datetime) -> int:
        async with self._lock:
            expired = [
                scan_id
                for scan_id, record in self._scans.items()
                if record.created_at < before
            ]
            for scan_id in expired:
                self._scans.pop(scan_id, None)
                self._adapter_runs.pop(scan_id, None)
                self._events.pop(scan_id, None)
                self._nodes.pop(scan_id, None)
                self._edges.pop(scan_id, None)
                self._provenance.pop(scan_id, None)
            return len(expired)

    async def close(self) -> None:
        self._healthy = False
