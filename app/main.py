from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Annotated
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from app.adapters.registry import ADAPTER_REGISTRY, get_target_model
from app.core.auth import AuthenticationError, OIDCVerifier, Principal, TokenVerifier
from app.core.config import Settings, settings
from app.core.logging import logger
from app.core.middleware import RequestBodyLimitMiddleware
from app.core.metrics import ProcessMetrics
from app.core.queueing import ArqScanQueue, ScanQueue
from app.core.rate_limit import RateLimiter, RedisRateLimiter
from app.schemas.platform import (
    AdapterRun,
    Case,
    GraphPage,
    Scan,
    ScanMode,
    ScanState,
    ScanTarget,
    TERMINAL_SCAN_STATES,
    utc_now,
)
from app.storage.base import Store, StoreError, finalize_cancelled_adapter_runs


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseCreate(APIModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def reject_blank_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("name must not be blank")
        return cleaned


class ScanCreate(APIModel):
    targets: list[ScanTarget] = Field(min_length=1, max_length=25)
    mode: ScanMode = ScanMode.PASSIVE
    adapter_ids: list[str] | None = Field(default=None, max_length=50)
    active_scan_confirmed: bool = False


class ScanDetail(Scan):
    adapter_runs: list[AdapterRun] = Field(default_factory=list)


class CapabilityAdapter(APIModel):
    adapter_id: str
    display_name: str
    target_types: tuple[str, ...]
    passive: bool
    enabled: bool
    unavailable_reason: str | None = None
    max_attempts: int = Field(ge=1)


class CapabilityPolicy(APIModel):
    passive_default: bool = True
    active_scanning_enabled: bool
    active_scanning_authorized: bool
    active_scope_configured: bool
    max_batch_size: int = Field(ge=1)


class CapabilitiesResponse(APIModel):
    adapters: list[CapabilityAdapter]
    dependencies: dict[str, bool]
    policy: CapabilityPolicy


@dataclass
class ServiceContainer:
    config: Settings
    store: Store | None = None
    queue: ScanQueue | None = None
    rate_limiter: RateLimiter | None = None
    verifier: TokenVerifier | None = None
    metrics: ProcessMetrics | None = None
    injected: bool = False
    startup_errors: tuple[str, ...] = ()
    store_initialized: bool = False
    dependency_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock, repr=False
    )


class StreamLimiter:
    def __init__(self, max_per_principal: int) -> None:
        self._max = max_per_principal
        self._counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, principal_id: str) -> bool:
        async with self._lock:
            current = self._counts.get(principal_id, 0)
            if current >= self._max:
                return False
            self._counts[principal_id] = current + 1
            return True

    async def release(self, principal_id: str) -> None:
        async with self._lock:
            current = self._counts.get(principal_id, 0)
            if current <= 1:
                self._counts.pop(principal_id, None)
            else:
                self._counts[principal_id] = current - 1


_bearer = HTTPBearer(auto_error=False)
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TRACEPARENT = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)


def _container(request: Request) -> ServiceContainer:
    return request.app.state.services


def _unavailable(operation: str, exc: Exception | None = None) -> HTTPException:
    context: dict[str, object] = {"operation": operation}
    if exc is not None:
        context["error_type"] = type(exc).__name__
    logger.bind(**context).error("service_dependency_unavailable")
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="service dependency unavailable",
    )


async def _principal(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer)
    ],
) -> Principal:
    services = _container(request)
    if not services.config.AUTH_ENABLED:
        return Principal(subject=services.config.LOCAL_PRINCIPAL_SUB)
    authorization = request.headers.get("Authorization", "")
    if len(authorization.encode("utf-8", errors="replace")) > (
        services.config.MAX_AUTHORIZATION_HEADER_BYTES
    ):
        raise HTTPException(
            status_code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
            detail="authorization header too large",
        )
    limiter = services.rate_limiter
    if limiter is None:
        raise _unavailable("rate_limit")
    client_host = request.client.host if request.client is not None else "unknown"
    try:
        preauth_allowed = await limiter.allow(f"ip:{client_host}")
    except Exception as exc:
        raise _unavailable("rate_limit", exc) from exc
    if not preauth_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="request rate limit exceeded",
        )
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if services.verifier is None:
        raise _unavailable("authenticate")
    try:
        return await run_in_threadpool(services.verifier.verify, credentials.credentials)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def _limited_principal(
    request: Request, principal: Annotated[Principal, Depends(_principal)]
) -> Principal:
    limiter = _container(request).rate_limiter
    if limiter is None:
        raise _unavailable("rate_limit")
    try:
        allowed = await limiter.allow(f"principal:{principal.subject}")
    except Exception as exc:
        raise _unavailable("rate_limit", exc) from exc
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="request rate limit exceeded",
        )
    return principal


async def _operations_guard(
    request: Request,
    operations_token: Annotated[
        str | None, Header(alias="X-Operations-Token")
    ] = None,
) -> None:
    services = _container(request)
    if not services.config.AUTH_ENABLED:
        return
    configured = services.config.OPERATIONS_TOKEN
    if not configured:
        raise _unavailable("operations_authentication")
    if operations_token is None or not hmac.compare_digest(
        operations_token, configured
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="operations authentication required",
        )


def _services_or_503(request: Request) -> tuple[Store, ScanQueue]:
    services = _container(request)
    if services.store is None or services.queue is None:
        raise _unavailable("resolve_dependencies")
    return services.store, services.queue


def _idempotency_hash(
    owner_id: str, case_id: str, idempotency_key: str | None
) -> str | None:
    if idempotency_key is None:
        return None
    if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise HTTPException(status_code=422, detail="invalid idempotency key")
    payload = f"{owner_id}\x00{case_id}\x00{idempotency_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _scan_job_id(scan_id: str) -> str:
    digest = hashlib.sha256(scan_id.encode("utf-8")).hexdigest()
    return f"job_{digest[:32]}"


def _same_scan_request(scan: Scan, body: ScanCreate) -> bool:
    return (
        scan.targets == body.targets
        and scan.mode is body.mode
        and sorted(scan.adapter_ids or ()) == sorted(body.adapter_ids or ())
        and scan.active_scan_confirmed == body.active_scan_confirmed
    )


def _scan_payload(scan: Scan, adapter_runs: list[AdapterRun]) -> ScanDetail:
    return ScanDetail(**scan.model_dump(), adapter_runs=adapter_runs)


def _validate_scan_targets(targets: list[ScanTarget]) -> list[ScanTarget]:
    normalized: list[ScanTarget] = []
    for target in targets:
        model = get_target_model(target.target_type)
        if model is None:
            raise HTTPException(status_code=422, detail="unsupported target type")
        try:
            entity = model(value=target.target_value)
        except Exception as exc:
            raise HTTPException(status_code=422, detail="invalid scan target") from exc
        normalized.append(
            ScanTarget(
                target_type=target.target_type,
                target_value=str(entity.value),
            )
        )
    return normalized


def _validate_adapter_selection(request: ScanCreate, config: Settings) -> None:
    if not request.adapter_ids:
        return
    target_types = {target.target_type for target in request.targets}
    for adapter_id in request.adapter_ids:
        registration = ADAPTER_REGISTRY.get(adapter_id)
        if registration is None:
            raise HTTPException(status_code=422, detail="unknown adapter id")
        if not registration.metadata_for(config).enabled:
            raise HTTPException(status_code=422, detail="selected adapter is unavailable")
        if not target_types.intersection(registration.metadata.target_types):
            raise HTTPException(
                status_code=422, detail="adapter does not support requested targets"
            )
        if request.mode is ScanMode.PASSIVE and not registration.metadata.passive:
            raise HTTPException(
                status_code=422, detail="active adapter requires active scan mode"
            )


def _active_scope_matches(target: ScanTarget, allowlist: list[str]) -> list[str]:
    """Return explicit policy entries authorizing one active target."""
    address = None
    hostname = None
    if target.target_type == "ip":
        address = ipaddress.ip_address(target.target_value)
    elif target.target_type == "domain":
        hostname = target.target_value.casefold().rstrip(".")
    elif target.target_type == "url":
        parsed = urlsplit(target.target_value)
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        try:
            address = ipaddress.ip_address(hostname)
            hostname = None
        except ValueError:
            pass
    else:
        return []

    if address is not None and not address.is_global:
        return []

    matches: list[str] = []
    for raw_entry in allowlist:
        entry = raw_entry.strip()
        if entry.startswith("ip:") and address is not None:
            try:
                if address in ipaddress.ip_network(entry[3:], strict=False):
                    matches.append(entry)
            except ValueError:
                continue
        elif entry.startswith("domain:") and hostname:
            scoped_domain = entry[7:].casefold().rstrip(".")
            if hostname == scoped_domain or hostname.endswith(f".{scoped_domain}"):
                matches.append(entry)
    return matches


def _authorize_active_targets(
    targets: list[ScanTarget], config: Settings
) -> list[str]:
    if not config.ACTIVE_TARGET_ALLOWLIST:
        raise HTTPException(
            status_code=403,
            detail="active scanning has no configured target scope",
        )
    matched: set[str] = set()
    for target in targets:
        target_matches = _active_scope_matches(
            target, config.ACTIVE_TARGET_ALLOWLIST
        )
        if not target_matches:
            raise HTTPException(
                status_code=403,
                detail="active scan target is outside the authorized scope",
            )
        matched.update(target_matches)
    return sorted(matched)


async def _health(component: object | None) -> bool:
    if component is None:
        return False
    try:
        return bool(await component.health())
    except Exception:
        return False


async def _construct_production_services(services: ServiceContainer) -> None:
    await _repair_production_services(services)


async def _repair_production_services(services: ServiceContainer) -> None:
    """Retry safe dependency construction and one-time store initialization."""
    previous_errors = services.startup_errors
    errors: list[str] = []
    async with services.dependency_lock:
        try:
            if services.store is None:
                from app.storage.neo4j import Neo4jStore

                services.store = Neo4jStore(services.config)
            healthy = await asyncio.wait_for(services.store.health(), timeout=2)
            if not healthy:
                errors.append("store:connectivity")
            elif not services.store_initialized:
                initialize = getattr(services.store, "initialize", None)
                if initialize is not None:
                    await initialize()
                services.store_initialized = True
        except Exception as exc:
            errors.append(f"store:{type(exc).__name__}")

        try:
            if services.queue is None:
                from arq import create_pool
                from arq.connections import RedisSettings

                redis_pool = await create_pool(
                    RedisSettings(
                        host=services.config.REDIS_HOST,
                        port=services.config.REDIS_PORT,
                        database=services.config.REDIS_DATABASE,
                        username=services.config.REDIS_USERNAME,
                        password=services.config.REDIS_PASSWORD,
                        ssl=services.config.REDIS_SSL,
                    )
                )
                services.queue = ArqScanQueue(redis_pool)
        except Exception as exc:
            errors.append(f"queue:{type(exc).__name__}")

        try:
            if services.rate_limiter is None:
                from redis.asyncio import Redis

                redis_client = Redis(
                    host=services.config.REDIS_HOST,
                    port=services.config.REDIS_PORT,
                    db=services.config.REDIS_DATABASE,
                    username=services.config.REDIS_USERNAME,
                    password=services.config.REDIS_PASSWORD,
                    ssl=services.config.REDIS_SSL,
                )
                services.rate_limiter = RedisRateLimiter(
                    redis_client,
                    services.config.RATE_LIMIT_REQUESTS,
                    services.config.RATE_LIMIT_WINDOW_SECONDS,
                )
        except Exception as exc:
            errors.append(f"rate_limiter:{type(exc).__name__}")

        if services.config.AUTH_ENABLED and services.verifier is None:
            try:
                services.verifier = OIDCVerifier(services.config)
            except Exception as exc:
                errors.append(f"auth:{type(exc).__name__}")
        services.startup_errors = tuple(errors)

    if errors:
        logger.bind(dependencies=errors).error("production_dependencies_degraded")
    elif previous_errors:
        logger.info("production_dependencies_recovered")


async def _close_services(services: ServiceContainer) -> None:
    for dependency in (services.rate_limiter, services.queue, services.store):
        if dependency is None:
            continue
        try:
            await dependency.close()
        except Exception as exc:
            logger.bind(
                dependency_type=type(dependency).__name__,
                error_type=type(exc).__name__,
            ).error("dependency_close_failed")


async def _retention_loop(
    services: ServiceContainer, stop: asyncio.Event
) -> None:
    while not stop.is_set():
        if services.store is not None:
            try:
                deleted = await services.store.purge_expired(
                    utc_now() - timedelta(days=services.config.DATA_RETENTION_DAYS)
                )
                if deleted:
                    logger.bind(deleted_scans=deleted).info("retention_sweep_completed")
            except Exception as exc:
                logger.bind(error_type=type(exc).__name__).error(
                    "retention_sweep_failed"
                )
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=services.config.RETENTION_SWEEP_SECONDS
            )
        except asyncio.TimeoutError:
            continue


async def _dispatch_loop(
    services: ServiceContainer, stop: asyncio.Event
) -> None:
    """Repair queued dispatches and requeue workers whose durable lease expired."""
    while not stop.is_set():
        if services.store is not None and services.queue is not None:
            try:
                stale_before = utc_now() - timedelta(
                    seconds=services.config.RUNNING_SCAN_LEASE_SECONDS
                )
                pending = await services.store.list_pending_scans(
                    limit=100, stale_before=stale_before
                )
                for scan in pending:
                    if not scan.job_id:
                        continue
                    try:
                        if scan.cancel_requested:
                            await finalize_cancelled_adapter_runs(
                                services.store, scan.owner_id, scan.id
                            )
                            await services.store.acknowledge_cancellation(
                                scan.owner_id, scan.id
                            )
                            continue
                        if scan.state is ScanState.RUNNING:
                            recovery_job_id = (
                                f"{scan.id}-lease-{scan.worker_attempt + 1}"
                            )
                            recovered = await services.store.recover_stale_scan(
                                scan.owner_id,
                                scan.id,
                                stale_before=stale_before,
                                job_id=recovery_job_id,
                            )
                            if recovered is None:
                                continue
                            scan = recovered
                            logger.bind(
                                scan_id=scan.id,
                                outcome_code="worker_lease_expired",
                                worker_attempt=scan.worker_attempt,
                            ).warning("scan_worker_lease_recovered")
                        await services.queue.enqueue(
                            scan.id, scan.owner_id, scan.case_id, scan.job_id
                        )
                        if scan.outcome_code == "queue_retryable_failure":
                            await services.store.mark_scan_dispatched(
                                scan.owner_id,
                                scan.id,
                                job_id=scan.job_id,
                            )
                    except Exception as exc:
                        logger.bind(
                            scan_id=scan.id,
                            outcome_code="queue_retryable_failure",
                            error_type=type(exc).__name__,
                        ).warning("scan_dispatch_retry")
            except Exception as exc:
                logger.bind(error_type=type(exc).__name__).error(
                    "scan_dispatch_sweep_failed"
                )
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=services.config.DISPATCH_SWEEP_SECONDS
            )
        except asyncio.TimeoutError:
            continue


def create_app(
    config: Settings | None = None,
    *,
    store: Store | None = None,
    queue: ScanQueue | None = None,
    rate_limiter: RateLimiter | None = None,
    verifier: TokenVerifier | None = None,
) -> FastAPI:
    config = config or Settings()
    injected = any(
        dependency is not None
        for dependency in (store, queue, rate_limiter, verifier)
    )
    services = ServiceContainer(
        config=config,
        store=store,
        queue=queue,
        rate_limiter=rate_limiter,
        verifier=verifier,
        metrics=ProcessMetrics(),
        injected=injected,
        store_initialized=store is not None,
    )
    stream_limiter = StreamLimiter(config.SCAN_EVENT_MAX_CONNECTIONS_PER_PRINCIPAL)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if not services.injected:
            await _construct_production_services(services)
        retention_stop = asyncio.Event()
        retention_task = (
            asyncio.create_task(_retention_loop(services, retention_stop))
            if not services.injected or services.store is not None
            else None
        )
        dispatch_task = (
            asyncio.create_task(_dispatch_loop(services, retention_stop))
            if not services.injected
            else None
        )
        try:
            yield
        finally:
            retention_stop.set()
            if retention_task is not None:
                await retention_task
            if dispatch_task is not None:
                await dispatch_task
            await _close_services(services)

    application = FastAPI(
        title="RECON OSINT API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if config.ENABLE_API_DOCS else None,
        redoc_url="/redoc" if config.ENABLE_API_DOCS else None,
        openapi_url="/openapi.json" if config.ENABLE_API_DOCS else None,
    )
    application.state.services = services
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.CORS_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "traceparent",
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Operations-Token",
        ],
        expose_headers=["X-Request-ID", "X-Correlation-ID", "traceparent"],
    )
    application.add_middleware(
        RequestBodyLimitMiddleware, max_bytes=config.MAX_REQUEST_BODY_BYTES
    )

    @application.middleware("http")
    async def request_outcomes(request: Request, call_next):
        request_id = request.headers.get("X-Correlation-ID", "") or request.headers.get(
            "X-Request-ID", ""
        )
        if not request_id or len(request_id) > 128 or any(
            character in request_id for character in "\r\n"
        ):
            request_id = uuid4().hex
        trace_match = _TRACEPARENT.fullmatch(
            request.headers.get("traceparent", "").casefold()
        )
        if (
            trace_match
            and trace_match.group(1) != "0" * 32
            and trace_match.group(2) != "0" * 16
        ):
            trace_id = trace_match.group(1)
            trace_flags = trace_match.group(3)
        else:
            trace_id = secrets.token_hex(16)
            trace_flags = "01"
        span_id = secrets.token_hex(8)
        traceparent = f"00-{trace_id}-{span_id}-{trace_flags}"
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            status_code = response.status_code if response is not None else 500
            if response is not None:
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Correlation-ID"] = request_id
                response.headers["traceparent"] = traceparent
            route = request.scope.get("route")
            route_path = getattr(route, "path", None) or "unmatched"
            services.metrics.record_http(request.method, route_path, status_code)
            logger.bind(
                request_id=request_id,
                trace_id=trace_id,
                span_id=span_id,
                method=request.method,
                path=route_path,
                status_code=status_code,
            ).info("http_request_outcome")

    @application.post("/v1/cases", status_code=status.HTTP_201_CREATED)
    async def create_case(
        body: CaseCreate,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
    ) -> Case:
        store, _ = _services_or_503(request)
        record = Case(
            owner_id=principal.subject,
            name=body.name,
            description=body.description,
        )
        try:
            return await store.create_case(record)
        except Exception as exc:
            raise _unavailable("create_case", exc) from exc

    @application.get("/v1/cases")
    async def list_cases(
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> list[Case]:
        store, _ = _services_or_503(request)
        try:
            return await store.list_cases(
                principal.subject, offset=offset, limit=limit
            )
        except Exception as exc:
            raise _unavailable("list_cases", exc) from exc

    @application.get("/v1/cases/{case_id}")
    async def get_case(
        case_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
    ) -> Case:
        store, _ = _services_or_503(request)
        try:
            record = await store.get_case(principal.subject, case_id)
        except Exception as exc:
            raise _unavailable("get_case", exc) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="case not found")
        return record

    @application.get("/v1/cases/{case_id}/scans")
    async def list_case_scans(
        case_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> list[Scan]:
        store, _ = _services_or_503(request)
        try:
            owned_case = await store.get_case(principal.subject, case_id)
            if owned_case is None:
                raise HTTPException(status_code=404, detail="case not found")
            return await store.list_case_scans(
                principal.subject, case_id, offset=offset, limit=limit
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise _unavailable("list_case_scans", exc) from exc

    @application.post(
        "/v1/cases/{case_id}/scans", status_code=status.HTTP_202_ACCEPTED
    )
    async def create_scan(
        case_id: str,
        body: ScanCreate,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
        idempotency_key: Annotated[
            str | None, Header(alias="Idempotency-Key")
        ] = None,
    ) -> Scan:
        store, queue = _services_or_503(request)
        if len(body.targets) > services.config.MAX_BATCH_SIZE:
            raise HTTPException(status_code=422, detail="scan batch limit exceeded")
        if body.adapter_ids and len(body.adapter_ids) > (
            services.config.MAX_ADAPTERS_PER_SCAN
        ):
            raise HTTPException(status_code=422, detail="adapter selection limit exceeded")
        weighted_cost = len(body.targets) + len(body.adapter_ids or ())
        if weighted_cost > 1:
            try:
                allowed = await services.rate_limiter.allow(
                    f"principal:{principal.subject}", cost=weighted_cost - 1
                )
            except Exception as exc:
                raise _unavailable("rate_limit", exc) from exc
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="weighted scan rate limit exceeded",
                )
        body = body.model_copy(
            update={"targets": _validate_scan_targets(body.targets)}
        )
        target_keys = {
            (target.target_type, target.target_value) for target in body.targets
        }
        if len(target_keys) != len(body.targets):
            raise HTTPException(status_code=422, detail="duplicate scan target")
        if body.adapter_ids and len(set(body.adapter_ids)) != len(body.adapter_ids):
            raise HTTPException(status_code=422, detail="duplicate adapter id")
        _validate_adapter_selection(body, services.config)
        active_scope: list[str] = []
        if body.mode is ScanMode.ACTIVE:
            if not services.config.ALLOW_ACTIVE_SCANNING:
                raise HTTPException(status_code=403, detail="active scanning is disabled")
            if not body.active_scan_confirmed:
                raise HTTPException(
                    status_code=400, detail="active scan confirmation is required"
                )
            if services.config.OIDC_ADMIN_ROLE not in principal.roles:
                raise HTTPException(
                    status_code=403, detail="active scanning requires administrator role"
                )
            active_scope = _authorize_active_targets(body.targets, services.config)
        try:
            owned_case = await store.get_case(principal.subject, case_id)
        except Exception as exc:
            raise _unavailable("get_case_for_scan", exc) from exc
        if owned_case is None:
            raise HTTPException(status_code=404, detail="case not found")

        request_hash = _idempotency_hash(
            principal.subject, case_id, idempotency_key
        )
        if request_hash is not None:
            try:
                existing = await store.get_scan_by_idempotency(
                    principal.subject, case_id, request_hash
                )
            except Exception as exc:
                raise _unavailable("get_idempotent_scan", exc) from exc
            if existing is not None:
                if not _same_scan_request(existing, body):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="idempotency key was already used for another scan",
                    )
                if existing.state is ScanState.QUEUED:
                    job_id = existing.job_id or _scan_job_id(existing.id)
                    try:
                        if existing.job_id != job_id:
                            existing = await store.set_scan_job_id(
                                principal.subject, existing.id, job_id
                            )
                        await queue.enqueue(
                            existing.id,
                            existing.owner_id,
                            existing.case_id,
                            job_id,
                        )
                    except Exception as exc:
                        raise _unavailable("redispatch_scan", exc) from exc
                return existing

        try:
            queue_depth = await queue.depth()
        except Exception as exc:
            raise _unavailable("scan_admission", exc) from exc
        if queue_depth >= services.config.MAX_QUEUE_DEPTH:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="scan queue capacity exceeded",
            )

        record = Scan(
            case_id=case_id,
            owner_id=principal.subject,
            targets=body.targets,
            mode=body.mode,
            adapter_ids=body.adapter_ids,
            active_scan_confirmed=body.active_scan_confirmed,
            active_authorized_at=(
                utc_now() if body.mode is ScanMode.ACTIVE else None
            ),
            active_authorized_by=(
                principal.subject if body.mode is ScanMode.ACTIVE else None
            ),
            active_scope=active_scope,
            idempotency_hash=request_hash,
        )
        record = record.model_copy(update={"job_id": _scan_job_id(record.id)})
        try:
            persisted = await store.create_scan(
                record,
                max_active=services.config.MAX_OUTSTANDING_SCANS_PER_PRINCIPAL,
            )
        except Exception as exc:
            if request_hash is not None:
                try:
                    existing = await store.get_scan_by_idempotency(
                        principal.subject, case_id, request_hash
                    )
                except Exception:
                    existing = None
                if existing is not None and _same_scan_request(existing, body):
                    try:
                        if existing.state is ScanState.QUEUED:
                            job_id = existing.job_id or _scan_job_id(existing.id)
                            if existing.job_id != job_id:
                                existing = await store.set_scan_job_id(
                                    principal.subject, existing.id, job_id
                                )
                            await queue.enqueue(
                                existing.id,
                                existing.owner_id,
                                existing.case_id,
                                job_id,
                            )
                    except Exception as dispatch_exc:
                        raise _unavailable(
                            "redispatch_scan", dispatch_exc
                        ) from dispatch_exc
                    return existing
            raise _unavailable("create_scan", exc) from exc
        if persisted is None:
            if request_hash is not None:
                try:
                    existing = await store.get_scan_by_idempotency(
                        principal.subject, case_id, request_hash
                    )
                except Exception as exc:
                    raise _unavailable("get_idempotent_scan", exc) from exc
                if existing is not None and _same_scan_request(existing, body):
                    return existing
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="outstanding scan quota exceeded",
            )
        if persisted.id != record.id:
            if not _same_scan_request(persisted, body):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="idempotency key was already used for another scan",
                )
            if persisted.state is ScanState.QUEUED and persisted.job_id:
                try:
                    await queue.enqueue(
                        persisted.id,
                        persisted.owner_id,
                        persisted.case_id,
                        persisted.job_id,
                    )
                except Exception as exc:
                    raise _unavailable("redispatch_scan", exc) from exc
            return persisted
        record = persisted
        try:
            await queue.enqueue(
                record.id, record.owner_id, record.case_id, record.job_id
            )
        except Exception as exc:
            try:
                current = await store.get_scan(principal.subject, record.id)
                if current is not None:
                    await store.update_scan(
                        current.model_copy(
                            update={
                                "outcome_code": "queue_retryable_failure",
                            }
                        )
                    )
            except Exception:
                pass
            raise _unavailable("enqueue_scan", exc) from exc
        services.metrics.record_created_scan()
        logger.bind(
            scan_id=record.id,
            case_id=record.case_id,
            owner_id=record.owner_id,
            mode=record.mode.value,
            target_count=len(record.targets),
        ).info("scan_created")
        return record

    @application.get("/v1/scans/{scan_id}")
    async def get_scan(
        scan_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
    ) -> ScanDetail:
        store, _ = _services_or_503(request)
        try:
            scan = await store.get_scan(principal.subject, scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="scan not found")
            runs = await store.list_adapter_runs(principal.subject, scan_id)
            return _scan_payload(scan, runs)
        except HTTPException:
            raise
        except Exception as exc:
            raise _unavailable("get_scan", exc) from exc

    @application.get("/v1/scans/{scan_id}/events")
    async def scan_events(
        scan_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
        last_event_id: Annotated[
            str | None, Header(alias="Last-Event-ID")
        ] = None,
    ) -> StreamingResponse:
        store, _ = _services_or_503(request)
        try:
            scan = await store.get_scan(principal.subject, scan_id)
        except Exception as exc:
            raise _unavailable("get_scan_events", exc) from exc
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if last_event_id is not None and len(last_event_id) > 128:
            raise HTTPException(status_code=400, detail="invalid last event id")
        if not await stream_limiter.acquire(principal.subject):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many concurrent progress streams",
            )

        async def stream():
            sent: set[str] = set()
            lifetime = float(services.config.SCAN_EVENT_MAX_SECONDS)
            if principal.expires_at is not None:
                lifetime = min(lifetime, max(0.0, principal.expires_at - time.time()))
            deadline = time.monotonic() + lifetime
            terminal = scan.state in TERMINAL_SCAN_STATES
            try:
                while time.monotonic() < deadline:
                    if await request.is_disconnected():
                        return
                    events = await store.list_events(principal.subject, scan_id)
                    if events is None:
                        return
                    if last_event_id and not sent:
                        event_ids = [event.id for event in events]
                        if last_event_id in event_ids:
                            resume_index = event_ids.index(last_event_id)
                            sent.update(event_ids[: resume_index + 1])
                    for event in events:
                        if event.id in sent:
                            continue
                        sent.add(event.id)
                        data = json.dumps(
                            event.model_dump(mode="json"), separators=(",", ":")
                        )
                        yield (
                            f"id: {event.id}\n"
                            f"event: {event.event_type}\n"
                            f"data: {data}\n\n"
                        )
                        terminal = (
                            event.event_type == "scan_status"
                            and event.state in TERMINAL_SCAN_STATES
                        )
                    if terminal:
                        return
                    await asyncio.sleep(services.config.SCAN_EVENT_POLL_SECONDS)
            finally:
                await stream_limiter.release(principal.subject)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "private, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @application.get("/v1/scans/{scan_id}/graph", response_model=GraphPage)
    async def get_graph(
        scan_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
        cursor: str | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> GraphPage:
        store, _ = _services_or_503(request)
        try:
            page = await store.get_graph(
                principal.subject, scan_id, cursor=cursor, limit=limit
            )
        except StoreError as exc:
            if "cursor" in str(exc) or "limit" in str(exc):
                raise HTTPException(status_code=400, detail="invalid graph pagination") from exc
            raise _unavailable("get_graph", exc) from exc
        except Exception as exc:
            raise _unavailable("get_graph", exc) from exc
        if page is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return page

    @application.post(
        "/v1/scans/{scan_id}/cancel",
        status_code=status.HTTP_202_ACCEPTED,
        response_model=ScanDetail,
    )
    async def cancel_scan(
        scan_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
    ) -> ScanDetail:
        store, queue = _services_or_503(request)
        try:
            current = await store.get_scan(principal.subject, scan_id)
        except Exception as exc:
            raise _unavailable("get_scan_for_cancel", exc) from exc
        if current is None:
            raise HTTPException(status_code=404, detail="scan not found")

        if current.state in TERMINAL_SCAN_STATES:
            cancelled = current
        else:
            try:
                cancelled = await store.request_cancellation(
                    principal.subject, scan_id
                )
            except Exception as exc:
                raise _unavailable("request_scan_cancellation", exc) from exc
            if cancelled is None:
                raise HTTPException(status_code=404, detail="scan not found")

        abort_acknowledged = False
        if current.state not in TERMINAL_SCAN_STATES and current.job_id:
            try:
                abort_acknowledged = await queue.abort(current.job_id)
            except Exception as exc:
                logger.bind(
                    scan_id=scan_id,
                    outcome_code="cancellation_requested",
                    error_type=type(exc).__name__,
                ).warning("scan_abort_pending")

            try:
                refreshed = await store.get_scan(principal.subject, scan_id)
            except Exception as exc:
                raise _unavailable(
                    "refresh_scan_after_abort", exc
                ) from exc
            if refreshed is None:
                raise HTTPException(status_code=404, detail="scan not found")
            cancelled = refreshed

        if abort_acknowledged or cancelled.state is ScanState.CANCELLED:
            try:
                adapter_runs = await finalize_cancelled_adapter_runs(
                    store, principal.subject, scan_id
                )
                if cancelled.state not in TERMINAL_SCAN_STATES:
                    acknowledged_scan = await store.acknowledge_cancellation(
                        principal.subject, scan_id
                    )
                    if acknowledged_scan is None:
                        raise StoreError("owned scan disappeared")
                    cancelled = acknowledged_scan
            except Exception as exc:
                raise _unavailable("acknowledge_scan_cancellation", exc) from exc
        else:
            try:
                adapter_runs = await store.list_adapter_runs(
                    principal.subject, cancelled.id
                )
            except Exception as exc:
                raise _unavailable("list_adapter_runs_after_cancel", exc) from exc

        if cancelled.state is ScanState.CANCELLED:
            if current.state is not ScanState.CANCELLED:
                services.metrics.record_cancelled_scan()
                log_event = "scan_cancelled"
            else:
                log_event = "scan_cancellation_noop"
        elif cancelled.cancel_requested:
            log_event = "scan_cancellation_requested"
        else:
            log_event = "scan_cancellation_noop"
        logger.bind(
            scan_id=scan_id,
            case_id=cancelled.case_id,
            owner_id=cancelled.owner_id,
            state=cancelled.state.value,
            outcome_code=cancelled.outcome_code,
        ).info(log_event)
        return ScanDetail(
            **cancelled.model_dump(), adapter_runs=adapter_runs
        )

    @application.get("/v1/capabilities", response_model=CapabilitiesResponse)
    async def capabilities(
        request: Request,
        principal: Annotated[Principal, Depends(_limited_principal)],
    ):
        if not services.injected and services.startup_errors:
            await _repair_production_services(services)
        store, queue = _services_or_503(request)
        dependency_health = {
            "store": await _health(store),
            "queue": await _health(queue),
            "rate_limiter": await _health(services.rate_limiter),
            "auth": (not services.config.AUTH_ENABLED or services.verifier is not None),
            "startup": not services.startup_errors,
        }
        adapters = [
            asdict(registration.metadata_for(services.config))
            for registration in ADAPTER_REGISTRY.values()
        ]
        payload = CapabilitiesResponse(
            adapters=adapters,
            dependencies=dependency_health,
            policy=CapabilityPolicy(
                active_scanning_enabled=services.config.ALLOW_ACTIVE_SCANNING,
                active_scanning_authorized=(
                    services.config.OIDC_ADMIN_ROLE in principal.roles
                ),
                active_scope_configured=bool(
                    services.config.ACTIVE_TARGET_ALLOWLIST
                ),
                max_batch_size=services.config.MAX_BATCH_SIZE,
            ),
        )
        return JSONResponse(
            payload.model_dump(mode="json"),
            status_code=(
                status.HTTP_200_OK
                if all(dependency_health.values())
                else status.HTTP_503_SERVICE_UNAVAILABLE
            ),
        )

    @application.get("/health/live")
    async def liveness() -> dict[str, str]:
        return {"status": "live"}

    @application.get("/health/ready")
    async def readiness(
        request: Request,
        _: Annotated[None, Depends(_operations_guard)],
    ):
        current = _container(request)
        if not current.injected and current.startup_errors:
            await _repair_production_services(current)
        health = {
            "store": await _health(current.store),
            "queue": await _health(current.queue),
            "rate_limiter": await _health(current.rate_limiter),
            "auth": (not current.config.AUTH_ENABLED or current.verifier is not None),
            "startup": not current.startup_errors,
        }
        return JSONResponse(
            {"status": "ready" if all(health.values()) else "not_ready", **health},
            status_code=(
                status.HTTP_200_OK
                if all(health.values())
                else status.HTTP_503_SERVICE_UNAVAILABLE
            ),
        )

    @application.get("/metrics", response_class=PlainTextResponse)
    async def metrics(
        _: Annotated[None, Depends(_operations_guard)],
    ) -> str:
        queue_depth: int | None = None
        shared_adapter_metrics = None
        if services.queue is not None:
            try:
                queue_depth = await services.queue.depth()
                shared_adapter_metrics = (
                    await services.queue.shared_adapter_metrics()
                )
            except Exception:
                pass
        return services.metrics.render(
            queue_depth=queue_depth,
            shared_adapter_metrics=shared_adapter_metrics,
        )

    return application


app = create_app(settings)
