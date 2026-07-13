import asyncio
import hashlib
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Dict

from arq import Retry

from app.adapters.registry import get_adapter_registrations, get_target_model
from app.core.logging import logger
from app.core.config import Settings, settings
from app.core.queueing import (
    ADAPTER_LATENCY_COUNT_METRICS_KEY,
    ADAPTER_LATENCY_SUM_METRICS_KEY,
    ADAPTER_OUTCOME_METRICS_KEY,
)
from app.redaction import redact_entities, redact_entity
from app.schemas.outcomes import (
    AdapterOutcome,
    AdapterState,
    ScanOutcome,
    ScanState,
)
from app.schemas.platform import (
    AdapterRun,
    Scan,
    ScanEvent,
    ScanMode,
    ScanState as PlatformScanState,
    TERMINAL_SCAN_STATES,
    utc_now,
)
from app.storage.base import (
    Store,
    StoreError,
    finalize_cancelled_adapter_runs,
)


def _scan_identifier(
    ctx: Dict[str, Any], target_type: str, target_value: str
) -> str:
    job_id = ctx.get("job_id")
    if job_id:
        job_digest = hashlib.sha256(
            str(job_id).encode("utf-8", errors="replace")
        ).hexdigest()
        return f"job-{job_digest[:16]}"
    digest = hashlib.sha256(
        f"{target_type}\x00{target_value}".encode("utf-8", errors="replace")
    ).hexdigest()
    return f"scan-{digest[:16]}"


def _scan_outcome(
    *,
    scan_id: str,
    target_type: str,
    state: ScanState,
    adapter_outcomes: tuple[AdapterOutcome, ...] = (),
    discovered_count: int = 0,
    code: str,
) -> ScanOutcome:
    outcome = ScanOutcome(
        scan_id=scan_id,
        target_type=target_type,
        state=state,
        adapter_outcomes=adapter_outcomes,
        discovered_count=discovered_count,
        code=code,
    )
    logger.bind(
        scan_id=scan_id,
        target_type=target_type,
        outcome_code=code,
        discovered_count=discovered_count,
    ).info("scan_task_outcome")
    return outcome


async def run_scan_task(
    ctx: Dict[str, Any], target_type: str, target_value: str
) -> ScanOutcome:
    """
    Dispatch a scan using only the explicit target and adapter registries.
    """
    scan_id = _scan_identifier(ctx, target_type, target_value)
    scan_logger = logger.bind(scan_id=scan_id, target_type=target_type)
    scan_logger.info("scan_task_started")

    entity_model = get_target_model(target_type)
    if entity_model is None:
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.FAILED,
            code="unsupported_target_type",
        )

    try:
        target = entity_model(value=target_value)
    except Exception:
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.FAILED,
            code="invalid_target",
        )

    config = ctx.get("settings", settings)
    if not isinstance(config, Settings):
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.FAILED,
            code="invalid_worker_settings",
        )

    adapter_outcomes: list[AdapterOutcome] = []
    for registration in get_adapter_registrations(target_type):
        adapter = registration.create(config)
        outcome = await adapter.execute(target)
        adapter_outcomes.append(outcome)
        scan_logger.bind(
            adapter_id=outcome.adapter_id,
            outcome_code=outcome.code,
        ).info("scan_adapter_outcome")

    outcomes = tuple(adapter_outcomes)
    failed = any(item.state is AdapterState.FAILED for item in outcomes)
    retryable = any(
        item.state is AdapterState.RETRYABLE_FAILURE for item in outcomes
    )
    findings = tuple(
        finding
        for outcome in outcomes
        if outcome.state is AdapterState.SUCCEEDED
        for finding in outcome.findings
    )

    if failed:
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.FAILED,
            adapter_outcomes=outcomes,
            discovered_count=len(findings),
            code="adapter_failed",
        )
    if retryable:
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.RETRYABLE_FAILURE,
            adapter_outcomes=outcomes,
            discovered_count=len(findings),
            code="adapter_retry_exhausted",
        )
    if not findings:
        if any(item.state is AdapterState.NO_RESULTS for item in outcomes):
            return _scan_outcome(
                scan_id=scan_id,
                target_type=target_type,
                state=ScanState.NO_RESULTS,
                adapter_outcomes=outcomes,
                code="no_findings",
            )
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.UNAVAILABLE,
            adapter_outcomes=outcomes,
            code="all_adapters_unavailable",
        )

    safe_findings = redact_entities(list(findings))
    safe_target = redact_entity(target)
    engine = None
    persistence_failed = False
    close_failed = False
    try:
        engine_factory = ctx.get("correlation_engine_factory")
        if engine_factory is None:
            from app.engine.correlation import CorrelationEngine

            engine_factory = CorrelationEngine
        engine = engine_factory()
        engine.add_entities(safe_findings, safe_target)
        correlation_result = engine.correlate()
        if (
            isinstance(correlation_result, dict)
            and correlation_result.get("status", "success") != "success"
        ):
            raise RuntimeError("correlation did not report success")
    except Exception:
        persistence_failed = True
    finally:
        if engine is not None:
            try:
                engine.close()
            except Exception:
                close_failed = True

    if persistence_failed or close_failed:
        return _scan_outcome(
            scan_id=scan_id,
            target_type=target_type,
            state=ScanState.FAILED,
            adapter_outcomes=outcomes,
            discovered_count=len(findings),
            code=(
                "persistence_close_failed"
                if close_failed and not persistence_failed
                else "persistence_failed"
            ),
        )

    return _scan_outcome(
        scan_id=scan_id,
        target_type=target_type,
        state=ScanState.SUCCEEDED,
        adapter_outcomes=outcomes,
        discovered_count=len(findings),
        code="persisted",
    )


@dataclass(frozen=True)
class AdapterExecution:
    outcome: AdapterOutcome
    adapter_version: str
    latency_seconds: float
    started_at: Any | None = None


def _eligible_case_registrations(scan: Scan, target, config: Settings) -> list:
    selected = []
    requested = set(scan.adapter_ids or ())
    for registration in get_adapter_registrations(target.target_type):
        metadata = registration.metadata_for(config)
        if not metadata.enabled:
            continue
        if requested and registration.adapter_id not in requested:
            continue
        if scan.mode is ScanMode.PASSIVE and not registration.metadata.passive:
            continue
        selected.append(registration)
    return selected


def _adapter_run_id(scan: Scan, target, adapter_id: str) -> str:
    digest = hashlib.sha256(
        "\x00".join(
            (scan.id, target.target_type, target.target_value, adapter_id)
        ).encode("utf-8", errors="replace")
    ).hexdigest()
    return f"run_{digest[:32]}"


def _case_scan_result(scan: Scan) -> dict[str, Any]:
    """Return the minimal non-sensitive result ARQ may retain or log."""
    return {
        "scan_id": scan.id,
        "state": scan.state.value,
        "outcome_code": scan.outcome_code,
    }


async def _terminal_or_cancelled_scan(
    store: Store, owner_id: str, scan_id: str
) -> Scan | None:
    """Return a terminal scan, acknowledging durable cancellation first."""
    current = await store.get_scan(owner_id, scan_id)
    if current is None:
        raise StoreError("owned scan disappeared")
    if current.cancel_requested:
        await finalize_cancelled_adapter_runs(store, owner_id, scan_id)
        current = await store.acknowledge_cancellation(owner_id, scan_id)
        if current is None:
            raise StoreError("owned scan disappeared")
    if current.state in TERMINAL_SCAN_STATES:
        return current
    return None


async def _maintain_scan_lease(
    store: Store,
    owner_id: str,
    scan_id: str,
    *,
    worker_attempt: int,
    interval_seconds: float,
    owner_task: asyncio.Task[Any],
) -> None:
    """Heartbeat a claimed scan and stop work promptly after lease loss."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            touched = await store.touch_scan_lease(
                owner_id, scan_id, worker_attempt=worker_attempt
            )
        except Exception as exc:
            logger.bind(
                scan_id=scan_id,
                worker_attempt=worker_attempt,
                error_type=type(exc).__name__,
            ).warning("scan_worker_lease_heartbeat_failed")
            continue
        if touched:
            continue
        try:
            current = await store.get_scan(owner_id, scan_id)
        except Exception:
            current = None
        if current is not None and current.state in TERMINAL_SCAN_STATES:
            return
        logger.bind(
            scan_id=scan_id,
            worker_attempt=worker_attempt,
            outcome_code="worker_lease_lost",
        ).warning("scan_worker_lease_lost")
        owner_task.cancel()
        return


async def _record_shared_adapter_metric(
    ctx: Dict[str, Any], adapter_id: str, outcome: str, latency: float
) -> None:
    redis = ctx.get("redis")
    if redis is None:
        return
    try:
        async with redis.pipeline(transaction=False) as pipeline:
            pipeline.hincrby(
                ADAPTER_OUTCOME_METRICS_KEY, f"{adapter_id}|{outcome}", 1
            )
            pipeline.hincrbyfloat(
                ADAPTER_LATENCY_SUM_METRICS_KEY, adapter_id, latency
            )
            pipeline.hincrby(ADAPTER_LATENCY_COUNT_METRICS_KEY, adapter_id, 1)
            await pipeline.execute()
    except Exception as exc:
        logger.bind(error_type=type(exc).__name__).warning(
            "adapter_metric_persistence_failed"
        )


async def _execute_case_adapters(
    scan: Scan, target, config: Settings, *, progress_callback=None
) -> list[AdapterExecution]:
    entity_model = get_target_model(target.target_type)
    if entity_model is None:
        return [
            AdapterExecution(
                AdapterOutcome(
                    adapter_id="platform",
                    state=AdapterState.FAILED,
                    code="unsupported_target_type",
                ),
                "v1",
                0,
            )
        ]
    try:
        entity = entity_model(value=target.target_value)
    except Exception:
        return [
            AdapterExecution(
                AdapterOutcome(
                    adapter_id="platform",
                    state=AdapterState.FAILED,
                    code="invalid_target",
                ),
                "v1",
                0,
            )
        ]

    selected = _eligible_case_registrations(scan, target, config)

    prepared = [
        (
            registration,
            registration.create(config),
        )
        for registration in selected
    ]
    if progress_callback is not None:
        for registration, adapter in prepared:
            await progress_callback(
                registration.adapter_id,
                str(getattr(adapter, "version", "v1")),
                AdapterState.QUEUED,
                None,
            )

    executions: list[AdapterExecution] = []
    for registration, adapter in prepared:
        started_at = utc_now()
        if progress_callback is not None:
            await progress_callback(
                registration.adapter_id,
                str(getattr(adapter, "version", "v1")),
                AdapterState.RUNNING,
                started_at,
            )
        started = time.perf_counter()
        try:
            outcome = await adapter.execute(entity)
        except asyncio.CancelledError:
            raise
        except Exception:
            outcome = AdapterOutcome(
                adapter_id=registration.adapter_id,
                state=AdapterState.FAILED,
                attempts=1,
                code="adapter_execution_error",
            )
        executions.append(
            AdapterExecution(
                outcome=outcome,
                adapter_version=str(getattr(adapter, "version", "v1")),
                latency_seconds=max(0.0, time.perf_counter() - started),
                started_at=started_at,
            )
        )
    return executions


async def run_case_scan_task(
    ctx: Dict[str, Any], scan_id: str, owner_id: str, case_id: str
) -> dict[str, Any]:
    """Execute one durable case scan without depending on live test services."""
    store = ctx.get("store")
    if not isinstance(store, Store):
        raise StoreError("case scan worker requires a durable store")
    config = ctx.get("settings", settings)
    if not isinstance(config, Settings):
        raise StoreError("case scan worker settings are invalid")

    current = await store.get_scan(owner_id, scan_id)
    if current is None or current.case_id != case_id:
        raise StoreError("owned scan does not exist")
    if current.cancel_requested:
        cancelled = await _terminal_or_cancelled_scan(
            store, owner_id, scan_id
        )
        if cancelled is None:
            raise StoreError("cancellation was not acknowledged")
        return _case_scan_result(cancelled)
    if current.state in TERMINAL_SCAN_STATES:
        return _case_scan_result(current)

    job_attempt = max(1, int(ctx.get("job_try", 1)))
    final_attempt = (
        "job_try" not in ctx or job_attempt >= config.WORKER_MAX_TRIES
    )
    worker_attempt = (
        max(job_attempt, current.worker_attempt + 1)
        if current.state is PlatformScanState.QUEUED
        else job_attempt
    )
    scan = await store.claim_scan(
        owner_id, scan_id, worker_attempt=worker_attempt
    )
    if scan is None:
        current = await store.get_scan(owner_id, scan_id)
        if current is None:
            raise StoreError("owned scan disappeared")
        if current.cancel_requested:
            current = await _terminal_or_cancelled_scan(
                store, owner_id, scan_id
            )
            if current is None:
                raise StoreError("cancellation was not acknowledged")
        return _case_scan_result(current)

    executor = ctx.get("adapter_executor", _execute_case_adapters)
    metrics = ctx.get("metrics")
    owner_task = asyncio.current_task()
    if owner_task is None:
        raise StoreError("case scan worker requires an active task")
    heartbeat_task = asyncio.create_task(
        _maintain_scan_lease(
            store,
            owner_id,
            scan_id,
            worker_attempt=worker_attempt,
            interval_seconds=config.WORKER_LEASE_HEARTBEAT_SECONDS,
            owner_task=owner_task,
        )
    )

    try:
        all_existing_runs = await store.list_adapter_runs(owner_id, scan_id)
        existing_runs = [
            run
            for run in all_existing_runs
            if run.state not in {AdapterState.QUEUED, AdapterState.RUNNING}
        ]
        execution_count = len(existing_runs)
        successful_outcomes = sum(
            run.state in {AdapterState.SUCCEEDED, AdapterState.NO_RESULTS}
            for run in existing_runs
        )
        failed_outcomes = execution_count - successful_outcomes
        finding_count = sum(run.finding_count for run in existing_runs)
        completed_keys = {
            (
                run.source_target.target_type,
                run.source_target.target_value,
                run.adapter_id,
            )
            for run in existing_runs
        }
        covered_targets = {
            (run.source_target.target_type, run.source_target.target_value)
            for run in existing_runs
        }

        from app.engine.correlation import build_finding_records
        from app.redaction import redact_entity

        for target in scan.targets:
            stopped = await _terminal_or_cancelled_scan(
                store, owner_id, scan_id
            )
            if stopped is not None:
                return _case_scan_result(stopped)

            execution_scan = scan
            if executor is _execute_case_adapters:
                eligible = _eligible_case_registrations(scan, target, config)
                remaining = [
                    registration.adapter_id
                    for registration in eligible
                    if (
                        target.target_type,
                        target.target_value,
                        registration.adapter_id,
                    )
                    not in completed_keys
                ]
                if eligible and not remaining:
                    executions = []
                elif not eligible:
                    executions = []
                else:
                    execution_scan = scan.model_copy(update={"adapter_ids": remaining})
                    async def progress_callback(
                        adapter_id,
                        adapter_version,
                        adapter_state,
                        started_at,
                    ):
                        if await _terminal_or_cancelled_scan(
                            store, owner_id, scan_id
                        ):
                            raise asyncio.CancelledError
                        await store.add_adapter_run(
                            AdapterRun(
                                id=_adapter_run_id(scan, target, adapter_id),
                                case_id=scan.case_id,
                                scan_id=scan.id,
                                owner_id=scan.owner_id,
                                adapter_id=adapter_id,
                                adapter_version=adapter_version,
                                source_target=target,
                                state=adapter_state,
                                started_at=started_at,
                                outcome_code=adapter_state.value,
                            ),
                            worker_attempt=worker_attempt,
                        )
                        await store.add_event(
                            ScanEvent(
                                case_id=scan.case_id,
                                scan_id=scan.id,
                                owner_id=scan.owner_id,
                                state=PlatformScanState.RUNNING,
                                outcome_code="running",
                                event_type="adapter_progress",
                                adapter_id=adapter_id,
                                adapter_state=adapter_state,
                            ),
                            worker_attempt=worker_attempt,
                        )

                    executions = await executor(
                        execution_scan,
                        target,
                        config,
                        progress_callback=progress_callback,
                    )
            else:
                executions = await executor(execution_scan, target, config)

            stopped = await _terminal_or_cancelled_scan(
                store, owner_id, scan_id
            )
            if stopped is not None:
                return _case_scan_result(stopped)

            for execution in executions:
                outcome = execution.outcome
                for finding in outcome.findings:
                    stopped = await _terminal_or_cancelled_scan(
                        store, owner_id, scan_id
                    )
                    if stopped is not None:
                        return _case_scan_result(stopped)
                    safe_finding = redact_entity(finding)
                    records = build_finding_records(
                        scan=scan,
                        source_target=target,
                        finding=safe_finding,
                        adapter_id=outcome.adapter_id,
                        adapter_version=execution.adapter_version,
                    )
                    await store.add_graph_records(
                        records.nodes,
                        records.edges,
                        records.provenance,
                        worker_attempt=worker_attempt,
                    )
                    finding_count += 1
                    stopped = await _terminal_or_cancelled_scan(
                        store, owner_id, scan_id
                    )
                    if stopped is not None:
                        return _case_scan_result(stopped)

                stopped = await _terminal_or_cancelled_scan(
                    store, owner_id, scan_id
                )
                if stopped is not None:
                    return _case_scan_result(stopped)
                await store.add_adapter_run(
                    AdapterRun(
                        id=_adapter_run_id(scan, target, outcome.adapter_id),
                        case_id=scan.case_id,
                        scan_id=scan.id,
                        owner_id=scan.owner_id,
                        adapter_id=outcome.adapter_id,
                        adapter_version=execution.adapter_version,
                        source_target=target,
                        state=outcome.state,
                        attempts=outcome.attempts,
                        finding_count=len(outcome.findings),
                        outcome_code=outcome.code,
                        started_at=execution.started_at,
                        finished_at=utc_now(),
                        latency_seconds=execution.latency_seconds,
                    ),
                    worker_attempt=worker_attempt,
                )
                await store.add_event(
                    ScanEvent(
                        case_id=scan.case_id,
                        scan_id=scan.id,
                        owner_id=scan.owner_id,
                        state=PlatformScanState.RUNNING,
                        outcome_code="running",
                        event_type="adapter_progress",
                        adapter_id=outcome.adapter_id,
                        adapter_state=outcome.state,
                    ),
                    worker_attempt=worker_attempt,
                )
                if metrics is not None:
                    metrics.record_adapter(
                        outcome.adapter_id,
                        outcome.state.value,
                        execution.latency_seconds,
                    )
                await _record_shared_adapter_metric(
                    ctx,
                    outcome.adapter_id,
                    outcome.state.value,
                    execution.latency_seconds,
                )
                execution_count += 1
                completed_keys.add(
                    (target.target_type, target.target_value, outcome.adapter_id)
                )
                covered_targets.add((target.target_type, target.target_value))
                if outcome.state in {
                    AdapterState.SUCCEEDED,
                    AdapterState.NO_RESULTS,
                }:
                    successful_outcomes += 1
                else:
                    failed_outcomes += 1

        uncovered_targets = sum(
            (target.target_type, target.target_value) not in covered_targets
            for target in scan.targets
        )
        if execution_count == 0:
            final_state = PlatformScanState.FAILED
            outcome_code = "no_adapters_available"
        elif successful_outcomes == 0:
            final_state = PlatformScanState.FAILED
            outcome_code = "adapter_failure"
        elif uncovered_targets:
            final_state = PlatformScanState.PARTIAL
            outcome_code = "incomplete_target_coverage"
        elif failed_outcomes:
            final_state = PlatformScanState.PARTIAL
            outcome_code = "adapter_partial_failure"
        else:
            final_state = PlatformScanState.SUCCEEDED
            outcome_code = "complete" if finding_count else "no_findings"

        finished = await store.finish_scan(
            owner_id,
            scan_id,
            worker_attempt=worker_attempt,
            state=final_state,
            outcome_code=outcome_code,
        )
        if finished is None:
            raise StoreError("owned scan disappeared")
        if finished.cancel_requested:
            finished = await _terminal_or_cancelled_scan(
                store, owner_id, scan_id
            )
            if finished is None:
                raise StoreError("cancellation was not acknowledged")
        logger.bind(
            scan_id=scan.id,
            state=finished.state.value,
            outcome_code=finished.outcome_code,
            adapter_outcomes=execution_count,
            finding_count=finding_count,
        ).info("case_scan_completed")
        return _case_scan_result(finished)
    except asyncio.CancelledError:
        stopped = await _terminal_or_cancelled_scan(store, owner_id, scan_id)
        if stopped is not None and stopped.state is PlatformScanState.CANCELLED:
            return _case_scan_result(stopped)
        raise
    except Exception as exc:
        failure_state = (
            PlatformScanState.FAILED
            if final_attempt
            else PlatformScanState.RUNNING
        )
        failure_code = (
            "worker_failure" if final_attempt else "retryable_worker_failure"
        )
        try:
            failed = await store.finish_scan(
                owner_id,
                scan_id,
                worker_attempt=worker_attempt,
                state=failure_state,
                outcome_code=failure_code,
            )
            if failed is not None and failed.cancel_requested:
                stopped = await _terminal_or_cancelled_scan(
                    store, owner_id, scan_id
                )
                if (
                    stopped is not None
                    and stopped.state is PlatformScanState.CANCELLED
                ):
                    return _case_scan_result(stopped)
        except Exception:
            pass
        logger.bind(
            scan_id=scan_id,
            outcome_code=failure_code,
            error_type=type(exc).__name__,
        ).error("case_scan_failed")
        if not final_attempt:
            raise Retry() from None
        raise RuntimeError("case scan execution failed") from None
    finally:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


async def startup_case_worker(ctx: Dict[str, Any]) -> None:
    """Construct and verify durable worker dependencies before accepting jobs."""
    config = ctx.get("settings", settings)
    if not isinstance(config, Settings):
        raise StoreError("case scan worker settings are invalid")
    ctx["settings"] = config
    store = ctx.get("store")
    if store is None:
        factory = ctx.get("store_factory")
        if factory is None:
            from app.storage.neo4j import Neo4jStore

            factory = Neo4jStore
        store = factory(config)
        if hasattr(store, "__await__"):
            store = await store
        ctx["store"] = store
    if not isinstance(store, Store):
        raise StoreError("case scan worker store is invalid")
    if not await store.health():
        await store.close()
        raise StoreError("case scan worker store is unavailable")
    initialize = getattr(store, "initialize", None)
    if initialize is not None:
        await initialize()
    if ctx.get("metrics") is None:
        from app.core.metrics import ProcessMetrics

        ctx["metrics"] = ProcessMetrics()


async def shutdown_case_worker(ctx: Dict[str, Any]) -> None:
    store = ctx.get("store")
    if isinstance(store, Store):
        await store.close()

try:
    from arq.connections import RedisSettings

    class WorkerSettings:
        """
        ARQ Worker Settings.
        """
        functions = [run_case_scan_task]
        redis_settings = RedisSettings(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            database=settings.REDIS_DATABASE,
            username=settings.REDIS_USERNAME,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
        )
        max_jobs = settings.MAX_CONCURRENT_TASKS
        max_tries = settings.WORKER_MAX_TRIES
        job_timeout = settings.WORKER_JOB_TIMEOUT_SECONDS
        retry_jobs = True
        allow_abort_jobs = True
        health_check_interval = settings.WORKER_HEALTH_INTERVAL_SECONDS
        log_results = False
        on_startup = startup_case_worker
        on_shutdown = shutdown_case_worker
except ImportError:
    logger.warning("arq not installed. Using dummy worker settings.")
    class WorkerSettings:  # type: ignore[no-redef]
        functions = [run_case_scan_task]
        redis_settings = None
        on_startup = startup_case_worker
        on_shutdown = shutdown_case_worker
