from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, TypeVar

from neo4j import AsyncGraphDatabase
from pydantic import BaseModel

from app.core.config import Settings
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


ModelT = TypeVar("ModelT", bound=BaseModel)


class Neo4jStore(Store):
    """Lifecycle-managed async Neo4j store with owner/case/scan scoping."""

    def __init__(self, config: Settings, *, driver: object | None = None) -> None:
        if driver is None:
            if not config.NEO4J_PASSWORD:
                raise ValueError("NEO4J_PASSWORD is required for the production store")
            driver = AsyncGraphDatabase.driver(
                config.NEO4J_URI,
                auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
            )
        self._driver = driver
        self._database = config.NEO4J_DATABASE

    @staticmethod
    def _records(result: object) -> list[Any]:
        records = getattr(result, "records", None)
        if records is not None:
            return list(records)
        if isinstance(result, tuple) and result:
            return list(result[0])
        raise StoreError("Neo4j returned an unexpected result")

    async def _run(self, query: str, parameters: dict[str, Any]) -> list[Any]:
        try:
            result = await self._driver.execute_query(
                query, parameters_=parameters, database_=self._database
            )
            return self._records(result)
        except StoreError:
            raise
        except Exception as exc:
            raise StoreError("Neo4j operation failed") from exc

    @staticmethod
    def _one(records: list[Any], model: type[ModelT]) -> ModelT | None:
        if not records:
            return None
        return model.model_validate_json(records[0]["payload"])

    async def health(self) -> bool:
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    async def initialize(self) -> None:
        """Create the uniqueness constraints required for safe idempotent writes."""
        constraints = (
            "CREATE CONSTRAINT case_id IF NOT EXISTS FOR (n:Case) REQUIRE n.id IS UNIQUE",
            (
                "CREATE CONSTRAINT scan_admission_owner IF NOT EXISTS "
                "FOR (n:ScanAdmission) REQUIRE n.owner_id IS UNIQUE"
            ),
            "CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (n:Scan) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT scan_idempotency_hash IF NOT EXISTS FOR (n:Scan) REQUIRE n.idempotency_hash IS UNIQUE",
            "CREATE CONSTRAINT adapter_run_id IF NOT EXISTS FOR (n:AdapterRun) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT graph_node_id IF NOT EXISTS FOR (n:GraphNode) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT graph_edge_id IF NOT EXISTS FOR (n:GraphEdge) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT provenance_id IF NOT EXISTS FOR (n:Provenance) REQUIRE n.id IS UNIQUE",
        )
        for query in constraints:
            await self._run(query, {})

    async def create_case(self, record: Case) -> Case:
        rows = await self._run(
            """
            CREATE (c:Case {
              id: $case_id, owner_id: $owner_id, payload: $payload,
              created_at: $created_at
            })
            RETURN c.payload AS payload
            """,
            {
                "case_id": record.id,
                "owner_id": record.owner_id,
                "payload": record.model_dump_json(),
                "created_at": record.created_at.isoformat(),
            },
        )
        persisted = self._one(rows, Case)
        if persisted is None:
            raise StoreError("Neo4j did not persist the case")
        return persisted

    async def list_cases(
        self, owner_id: str, *, offset: int = 0, limit: int
    ) -> list[Case]:
        if offset < 0 or not 1 <= limit <= 100:
            raise StoreError("case history limit must be between 1 and 100")
        rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})
            RETURN c.payload AS payload
            ORDER BY c.created_at DESC, c.id DESC
            SKIP $offset
            LIMIT $limit
            """,
            {"owner_id": owner_id, "offset": offset, "limit": limit},
        )
        return [Case.model_validate_json(row["payload"]) for row in rows]

    async def get_case(self, owner_id: str, case_id: str) -> Case | None:
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})
            RETURN c.payload AS payload
            """,
            {"owner_id": owner_id, "case_id": case_id},
        )
        return self._one(rows, Case)

    async def create_scan(
        self, record: Scan, *, max_active: int | None = None
    ) -> Scan | None:
        if max_active is not None and max_active < 1:
            raise StoreError("active scan quota must be positive")
        admission = (
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})
            MERGE (admission:ScanAdmission {owner_id: $owner_id})
            SET admission.serial = coalesce(admission.serial, 0) + 1
            WITH c, admission
            OPTIONAL MATCH (active:Scan {owner_id: $owner_id})
            WHERE active.state IN ['queued', 'running']
            WITH c, admission, count(active) AS active_count
            WHERE active_count < $max_active
            """
            if max_active is not None
            else "MATCH (c:Case {id: $case_id, owner_id: $owner_id})\n"
        )
        rows = await self._run(
            admission
            + """
            CREATE (s:Scan {
              id: $scan_id, case_id: $case_id, owner_id: $owner_id,
              idempotency_hash: $idempotency_hash,
              state: $state, outcome_code: $outcome_code,
              job_id: $job_id,
              cancel_requested: $cancel_requested,
              worker_attempt: $worker_attempt,
              payload: $payload, created_at: $created_at
            })
            CREATE (c)-[:HAS_SCAN]->(s)
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $created_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": record.owner_id,
                "case_id": record.case_id,
                "scan_id": record.id,
                "payload": record.model_dump_json(),
                "idempotency_hash": record.idempotency_hash,
                "state": record.state.value,
                "outcome_code": record.outcome_code,
                "job_id": record.job_id,
                "cancel_requested": record.cancel_requested,
                "worker_attempt": record.worker_attempt,
                "created_at": record.created_at.isoformat(),
                "event_id": f"initial-{record.id}",
                "event_payload": ScanEvent(
                    id=f"initial-{record.id}",
                    owner_id=record.owner_id,
                    case_id=record.case_id,
                    scan_id=record.id,
                    state=record.state,
                    outcome_code=record.outcome_code,
                ).model_dump_json(),
                "max_active": max_active,
            },
        )
        persisted = self._one(rows, Scan)
        if persisted is None and max_active is None:
            raise StoreError("owned case was not found for scan creation")
        return persisted

    async def get_scan(self, owner_id: str, scan_id: str) -> Scan | None:
        rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, owner_id: $owner_id})
            RETURN s.payload AS payload
            """,
            {"owner_id": owner_id, "scan_id": scan_id},
        )
        return self._one(rows, Scan)

    async def list_case_scans(
        self, owner_id: str, case_id: str, *, offset: int = 0, limit: int
    ) -> list[Scan]:
        if offset < 0 or not 1 <= limit <= 100:
            raise StoreError("case scan history limit must be between 1 and 100")
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->(s:Scan)
            RETURN s.payload AS payload
            ORDER BY s.created_at DESC, s.id DESC
            SKIP $offset
            LIMIT $limit
            """,
            {
                "owner_id": owner_id,
                "case_id": case_id,
                "offset": offset,
                "limit": limit,
            },
        )
        return [Scan.model_validate_json(row["payload"]) for row in rows]

    async def get_scan_by_idempotency(
        self, owner_id: str, case_id: str, idempotency_hash: str
    ) -> Scan | None:
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {
                    case_id: $case_id, owner_id: $owner_id,
                    idempotency_hash: $idempotency_hash
                  })
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": case_id,
                "idempotency_hash": idempotency_hash,
            },
        )
        return self._one(rows, Scan)

    async def list_pending_scans(
        self, *, limit: int, stale_before: datetime | None = None
    ) -> list[Scan]:
        if limit < 1:
            raise StoreError("pending scan limit must be positive")
        stale_clause = ""
        parameters: dict[str, Any] = {"limit": limit}
        if stale_before is not None:
            stale_clause = """
                OR (
                  s.state = 'running'
                  AND datetime(s.updated_at) < datetime($stale_before)
                )
            """
            parameters["stale_before"] = stale_before.isoformat()
        rows = await self._run(
            f"""
            MATCH (s:Scan)
            WHERE s.job_id IS NOT NULL
              AND (s.state = 'queued' {stale_clause})
            RETURN s.payload AS payload
            ORDER BY s.created_at, s.id
            LIMIT $limit
            """,
            parameters,
        )
        return [Scan.model_validate_json(row["payload"]) for row in rows]

    async def count_active_scans(self, owner_id: str) -> int:
        rows = await self._run(
            """
            MATCH (s:Scan {owner_id: $owner_id})
            WHERE s.state IN ['queued', 'running']
            RETURN count(s) AS active
            """,
            {"owner_id": owner_id},
        )
        return int(rows[0]["active"]) if rows else 0

    async def update_scan(self, record: Scan) -> Scan:
        updated = record.model_copy(update={"updated_at": utc_now()})
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, case_id: $case_id, owner_id: $owner_id})
            WITH s, s.state AS prior_state, s.outcome_code AS prior_outcome
            SET s.payload = $payload, s.updated_at = $updated_at,
                s.state = $state, s.outcome_code = $outcome_code,
                s.job_id = $job_id,
                s.cancel_requested = $cancel_requested,
                s.worker_attempt = $worker_attempt
            FOREACH (_ IN CASE
              WHEN coalesce(prior_state, '') <> $state
                OR coalesce(prior_outcome, '') <> coalesce($outcome_code, '')
              THEN [1] ELSE [] END |
              CREATE (event:ScanEvent {
                id: $event_id, scan_id: $scan_id, case_id: $case_id,
                owner_id: $owner_id, payload: $event_payload,
                created_at: $updated_at
              })
              CREATE (s)-[:HAS_EVENT]->(event)
            )
            RETURN s.payload AS payload
            """,
            {
                "owner_id": updated.owner_id,
                "case_id": updated.case_id,
                "scan_id": updated.id,
                "payload": updated.model_dump_json(),
                "state": updated.state.value,
                "outcome_code": updated.outcome_code,
                "job_id": updated.job_id,
                "cancel_requested": updated.cancel_requested,
                "worker_attempt": updated.worker_attempt,
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        persisted = self._one(rows, Scan)
        if persisted is None:
            raise StoreError("owned scan was not found")
        return persisted

    async def mark_scan_dispatched(
        self, owner_id: str, scan_id: str, *, job_id: str
    ) -> Scan | None:
        """Clear a retryable dispatch outcome with a field-level CAS."""
        current = await self.get_scan(owner_id, scan_id)
        if (
            current is None
            or current.state is not ScanState.QUEUED
            or current.job_id != job_id
            or current.cancel_requested
            or current.outcome_code != "queue_retryable_failure"
        ):
            return None
        updated = current.model_copy(
            update={"outcome_code": "queued", "updated_at": utc_now()}
        )
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE s.state = 'queued'
              AND s.job_id = $job_id
              AND s.outcome_code = 'queue_retryable_failure'
              AND coalesce(s.cancel_requested, false) = false
            SET s.payload = $payload, s.outcome_code = 'queued',
                s.updated_at = $updated_at
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $updated_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "job_id": job_id,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        return self._one(rows, Scan)

    async def claim_scan(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> Scan | None:
        if worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        current = await self.get_scan(owner_id, scan_id)
        if current is None:
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
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE coalesce(s.cancel_requested, false) = false
              AND (
                s.state = 'queued'
                OR (s.state = 'running' AND coalesce(s.worker_attempt, 0) < $worker_attempt)
              )
            SET s.payload = $payload, s.state = 'running',
                s.outcome_code = 'running', s.worker_attempt = $worker_attempt,
                s.updated_at = $updated_at
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $updated_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "worker_attempt": worker_attempt,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        return self._one(rows, Scan)

    async def touch_scan_lease(
        self, owner_id: str, scan_id: str, *, worker_attempt: int
    ) -> bool:
        if worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        current = await self.get_scan(owner_id, scan_id)
        if (
            current is None
            or current.state is not ScanState.RUNNING
            or current.worker_attempt != worker_attempt
            or current.cancel_requested
        ):
            return False
        updated = current.model_copy(update={"updated_at": utc_now()})
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
            SET s.payload = $payload, s.updated_at = $updated_at
            RETURN count(s) AS touched
            """,
            {
                "owner_id": owner_id,
                "scan_id": scan_id,
                "worker_attempt": worker_attempt,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
            },
        )
        return bool(rows and int(rows[0]["touched"]) == 1)

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
        current = await self.get_scan(owner_id, scan_id)
        if (
            current is None
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
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
              AND datetime(s.updated_at) < datetime($stale_before)
            SET s.payload = $payload, s.state = 'queued',
                s.outcome_code = 'worker_lease_expired',
                s.job_id = $job_id, s.updated_at = $updated_at
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $updated_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "worker_attempt": current.worker_attempt,
                "stale_before": stale_before.isoformat(),
                "job_id": job_id,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        return self._one(rows, Scan)

    async def finish_scan(
        self,
        owner_id: str,
        scan_id: str,
        *,
        worker_attempt: int,
        state: ScanState,
        outcome_code: str,
    ) -> Scan | None:
        current = await self.get_scan(owner_id, scan_id)
        if current is None:
            return None
        if (
            current.state is not ScanState.RUNNING
            or current.worker_attempt != worker_attempt
            or current.cancel_requested
        ):
            return current
        updated = current.model_copy(
            update={
                "state": state,
                "outcome_code": outcome_code,
                "finished_at": utc_now() if state in TERMINAL_SCAN_STATES else None,
                "updated_at": utc_now(),
            }
        )
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
            WITH s, s.state AS prior_state, s.outcome_code AS prior_outcome
            SET s.payload = $payload, s.state = $state,
                s.outcome_code = $outcome_code, s.updated_at = $updated_at
            FOREACH (_ IN CASE
              WHEN prior_state <> $state
                OR coalesce(prior_outcome, '') <> coalesce($outcome_code, '')
              THEN [1] ELSE [] END |
              CREATE (event:ScanEvent {
                id: $event_id, scan_id: $scan_id, case_id: $case_id,
                owner_id: $owner_id, payload: $event_payload,
                created_at: $updated_at
              })
              CREATE (s)-[:HAS_EVENT]->(event)
            )
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "worker_attempt": worker_attempt,
                "state": state.value,
                "outcome_code": outcome_code,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        persisted = self._one(rows, Scan)
        return persisted if persisted is not None else await self.get_scan(owner_id, scan_id)

    async def set_scan_job_id(
        self, owner_id: str, scan_id: str, job_id: str
    ) -> Scan:
        record = await self.get_scan(owner_id, scan_id)
        if record is None:
            raise StoreError("owned scan was not found")
        return await self.update_scan(record.model_copy(update={"job_id": job_id}))

    async def request_cancellation(
        self, owner_id: str, scan_id: str
    ) -> Scan | None:
        record = await self.get_scan(owner_id, scan_id)
        if record is None:
            return None
        if record.state in TERMINAL_SCAN_STATES:
            return record
        updated = record.model_copy(
            update={
                "cancel_requested": True,
                "outcome_code": "cancellation_requested",
                "updated_at": utc_now(),
            }
        )
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE NOT s.state IN ['succeeded', 'partial', 'failed', 'cancelled']
            SET s.payload = $payload, s.cancel_requested = true,
                s.outcome_code = 'cancellation_requested',
                s.updated_at = $updated_at
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $updated_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        persisted = self._one(rows, Scan)
        return persisted if persisted is not None else await self.get_scan(owner_id, scan_id)

    async def acknowledge_cancellation(
        self, owner_id: str, scan_id: str
    ) -> Scan | None:
        record = await self.get_scan(owner_id, scan_id)
        if record is None or record.state in TERMINAL_SCAN_STATES:
            return record
        if not record.cancel_requested:
            return record
        updated = record.model_copy(
            update={
                "state": ScanState.CANCELLED,
                "finished_at": utc_now(),
                "outcome_code": "cancelled",
                "updated_at": utc_now(),
            }
        )
        event = ScanEvent(
            owner_id=updated.owner_id,
            case_id=updated.case_id,
            scan_id=updated.id,
            state=updated.state,
            outcome_code=updated.outcome_code,
        )
        rows = await self._run(
            """
            MATCH (s:Scan {id: $scan_id, owner_id: $owner_id})
            WHERE coalesce(s.cancel_requested, false) = true
              AND NOT s.state IN ['succeeded', 'partial', 'failed', 'cancelled']
            SET s.payload = $payload, s.state = 'cancelled',
                s.outcome_code = 'cancelled', s.updated_at = $updated_at
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $event_payload,
              created_at: $updated_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN s.payload AS payload
            """,
            {
                "owner_id": owner_id,
                "case_id": updated.case_id,
                "scan_id": scan_id,
                "payload": updated.model_dump_json(),
                "updated_at": updated.updated_at.isoformat(),
                "event_id": event.id,
                "event_payload": event.model_dump_json(),
            },
        )
        persisted = self._one(rows, Scan)
        return persisted if persisted is not None else await self.get_scan(owner_id, scan_id)

    async def add_adapter_run(
        self, record: AdapterRun, *, worker_attempt: int | None = None
    ) -> AdapterRun:
        if worker_attempt is not None and worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, case_id: $case_id, owner_id: $owner_id})
            WHERE $worker_attempt IS NULL OR (
              s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
            )
            MERGE (run:AdapterRun {
              id: $run_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id
            })
            SET run.payload = $payload, run.created_at = $created_at
            MERGE (s)-[:HAS_ADAPTER_RUN]->(run)
            RETURN run.payload AS payload
            """,
            {
                "owner_id": record.owner_id,
                "case_id": record.case_id,
                "scan_id": record.scan_id,
                "worker_attempt": worker_attempt,
                "run_id": record.id,
                "payload": record.model_dump_json(),
                "created_at": (
                    record.finished_at or record.started_at or utc_now()
                ).isoformat(),
            },
        )
        persisted = self._one(rows, AdapterRun)
        if persisted is None:
            if worker_attempt is not None:
                raise StoreError("scan lease was lost before adapter run persistence")
            raise StoreError("owned scan was not found for adapter run")
        return persisted

    async def list_adapter_runs(
        self, owner_id: str, scan_id: str
    ) -> list[AdapterRun]:
        rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, owner_id: $owner_id})-[:HAS_ADAPTER_RUN]->
                  (run:AdapterRun {scan_id: $scan_id, owner_id: $owner_id})
            RETURN run.payload AS payload
            ORDER BY run.created_at, run.id
            """,
            {"owner_id": owner_id, "scan_id": scan_id},
        )
        return [AdapterRun.model_validate_json(row["payload"]) for row in rows]

    async def add_event(
        self, event: ScanEvent, *, worker_attempt: int | None = None
    ) -> ScanEvent:
        if worker_attempt is not None and worker_attempt < 1:
            raise StoreError("worker attempt must be positive")
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, case_id: $case_id, owner_id: $owner_id})
            WHERE $worker_attempt IS NULL OR (
              s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
            )
            CREATE (event:ScanEvent {
              id: $event_id, scan_id: $scan_id, case_id: $case_id,
              owner_id: $owner_id, payload: $payload,
              created_at: $created_at
            })
            CREATE (s)-[:HAS_EVENT]->(event)
            RETURN event.payload AS payload
            """,
            {
                "owner_id": event.owner_id,
                "case_id": event.case_id,
                "scan_id": event.scan_id,
                "worker_attempt": worker_attempt,
                "event_id": event.id,
                "payload": event.model_dump_json(),
                "created_at": event.created_at.isoformat(),
            },
        )
        persisted = self._one(rows, ScanEvent)
        if persisted is None:
            if worker_attempt is not None:
                raise StoreError("scan lease was lost before event persistence")
            raise StoreError("owned scan was not found for event")
        return persisted

    async def list_events(
        self, owner_id: str, scan_id: str
    ) -> list[ScanEvent] | None:
        scan = await self.get_scan(owner_id, scan_id)
        if scan is None:
            return None
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, case_id: $case_id, owner_id: $owner_id})
                  -[:HAS_EVENT]->(event:ScanEvent {
                    scan_id: $scan_id, case_id: $case_id, owner_id: $owner_id
                  })
            RETURN event.payload AS payload
            ORDER BY event.created_at, event.id
            """,
            {
                "owner_id": owner_id,
                "case_id": scan.case_id,
                "scan_id": scan_id,
            },
        )
        return [ScanEvent.model_validate_json(row["payload"]) for row in rows]

    @staticmethod
    def _scope(records: Sequence[BaseModel]) -> tuple[str, str, str]:
        first = records[0]
        scope = (first.owner_id, first.case_id, first.scan_id)
        if any(
            (record.owner_id, record.case_id, record.scan_id) != scope
            for record in records
        ):
            raise StoreError("graph records must share one owner/case/scan scope")
        return scope

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
        records: list[BaseModel] = [*nodes, *edges, *provenance]
        if not records:
            return
        owner_id, case_id, scan_id = self._scope(records)
        rows = await self._run(
            """
            MATCH (c:Case {id: $case_id, owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, case_id: $case_id, owner_id: $owner_id})
            WHERE $worker_attempt IS NULL OR (
              s.state = 'running'
              AND coalesce(s.worker_attempt, 0) = $worker_attempt
              AND coalesce(s.cancel_requested, false) = false
            )
            FOREACH (item IN $nodes |
              MERGE (n:GraphNode {
                id: item.id, scan_id: $scan_id, case_id: $case_id,
                owner_id: $owner_id
              })
              SET n.payload = item.payload
              MERGE (s)-[:HAS_GRAPH_NODE]->(n)
            )
            FOREACH (item IN $edges |
              MERGE (e:GraphEdge {
                id: item.id, scan_id: $scan_id, case_id: $case_id,
                owner_id: $owner_id
              })
              SET e.payload = item.payload,
                  e.source_node_id = item.source_node_id,
                  e.target_node_id = item.target_node_id
              MERGE (s)-[:HAS_GRAPH_EDGE]->(e)
            )
            FOREACH (item IN $provenance |
              MERGE (p:Provenance {
                id: item.id, scan_id: $scan_id, case_id: $case_id,
                owner_id: $owner_id
              })
              SET p.payload = item.payload, p.node_id = item.node_id,
                  p.edge_id = item.edge_id
              MERGE (s)-[:HAS_PROVENANCE]->(p)
            )
            RETURN count(s) AS persisted
            """,
            {
                "owner_id": owner_id,
                "case_id": case_id,
                "scan_id": scan_id,
                "worker_attempt": worker_attempt,
                "nodes": [
                    {"id": item.id, "payload": item.model_dump_json()}
                    for item in nodes
                ],
                "edges": [
                    {
                        "id": item.id,
                        "source_node_id": item.source_node_id,
                        "target_node_id": item.target_node_id,
                        "payload": item.model_dump_json(),
                    }
                    for item in edges
                ],
                "provenance": [
                    {
                        "id": item.id,
                        "node_id": item.node_id,
                        "edge_id": item.edge_id,
                        "payload": item.model_dump_json(),
                    }
                    for item in provenance
                ],
            },
        )
        if not rows or int(rows[0]["persisted"]) != 1:
            if worker_attempt is not None:
                raise StoreError("scan lease was lost before graph persistence")
            raise StoreError("owned scan was not found for graph persistence")

    async def get_graph(
        self, owner_id: str, scan_id: str, *, cursor: str | None, limit: int
    ) -> GraphPage | None:
        if not 1 <= limit <= 200:
            raise StoreError("graph limit must be between 1 and 200")
        node_offset, edge_offset, provenance_offset = decode_graph_cursor(cursor)
        if await self.get_scan(owner_id, scan_id) is None:
            return None
        common = {"owner_id": owner_id, "scan_id": scan_id}
        node_rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, owner_id: $owner_id})-[:HAS_GRAPH_NODE]->
                  (n:GraphNode {scan_id: $scan_id, owner_id: $owner_id})
            RETURN n.payload AS payload
            ORDER BY n.id
            SKIP $offset LIMIT $fetch_limit
            """,
            {**common, "offset": node_offset, "fetch_limit": limit + 1},
        )
        more_nodes = len(node_rows) > limit
        nodes = [
            GraphNode.model_validate_json(row["payload"])
            for row in node_rows[:limit]
        ]
        edge_rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, owner_id: $owner_id})-[:HAS_GRAPH_EDGE]->
                  (e:GraphEdge {scan_id: $scan_id, owner_id: $owner_id})
            RETURN e.payload AS payload
            ORDER BY e.id
            SKIP $offset LIMIT $fetch_limit
            """,
            {**common, "offset": edge_offset, "fetch_limit": limit + 1},
        )
        more_edges = len(edge_rows) > limit
        edges = [
            GraphEdge.model_validate_json(row["payload"])
            for row in edge_rows[:limit]
        ]
        provenance_rows = await self._run(
            """
            MATCH (c:Case {owner_id: $owner_id})-[:HAS_SCAN]->
                  (s:Scan {id: $scan_id, owner_id: $owner_id})-[:HAS_PROVENANCE]->
                  (p:Provenance {scan_id: $scan_id, owner_id: $owner_id})
            RETURN p.payload AS payload
            ORDER BY p.id
            SKIP $offset LIMIT $fetch_limit
            """,
            {
                **common,
                "offset": provenance_offset,
                "fetch_limit": limit + 1,
            },
        )
        more_provenance = len(provenance_rows) > limit
        provenance = [
            Provenance.model_validate_json(row["payload"])
            for row in provenance_rows[:limit]
        ]
        next_node = node_offset + len(nodes)
        next_edge = edge_offset + len(edges)
        next_provenance = provenance_offset + len(provenance)
        return GraphPage(
            nodes=nodes,
            edges=edges,
            provenance=provenance,
            next_cursor=(
                encode_graph_cursor(next_node, next_edge, next_provenance)
                if more_nodes or more_edges or more_provenance
                else None
            ),
        )

    async def purge_expired(self, before: datetime) -> int:
        rows = await self._run(
            """
            MATCH (s:Scan)
            WHERE datetime(s.created_at) < datetime($before)
            OPTIONAL MATCH (s)-[]->(artifact)
            WITH collect(DISTINCT s) AS scans,
                 [item IN collect(DISTINCT artifact) WHERE item IS NOT NULL] AS artifacts
            FOREACH (item IN artifacts | DETACH DELETE item)
            FOREACH (item IN scans | DETACH DELETE item)
            RETURN size(scans) AS deleted
            """,
            {"before": before.isoformat()},
        )
        return int(rows[0]["deleted"]) if rows else 0

    async def close(self) -> None:
        await self._driver.close()
