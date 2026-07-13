from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.adapters.ip import ShodanAdapter
from app.core.config import Settings
from app.schemas.entities import DomainEntity, IPEntity
from app.schemas.outcomes import RetryableAdapterError
from app import worker


def _worker_api():
    from app.schemas.outcomes import ScanState

    return ScanState


@dataclass
class RecordingLogger:
    records: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def bind(self, **context: Any) -> "RecordingLogger":
        return RecordingLogger(self.records, {**self.context, **context})

    def info(self, message: str) -> None:
        self.records.append((message, self.context))

    def warning(self, message: str) -> None:
        self.records.append((message, self.context))

    def error(self, message: str) -> None:
        self.records.append((message, self.context))


class RecordingEngine:
    def __init__(self, *, fail_add: bool = False, fail_correlate: bool = False):
        self.fail_add = fail_add
        self.fail_correlate = fail_correlate
        self.added: list[Any] = []
        self.source = None
        self.correlated = False
        self.closed = False

    def add_entities(self, entities, source_entity) -> None:
        if self.fail_add:
            raise RuntimeError("database unavailable")
        self.added = list(entities)
        self.source = source_entity

    def correlate(self):
        if self.fail_correlate:
            raise RuntimeError("correlation failed")
        self.correlated = True
        return {"status": "success"}

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_worker_reports_unavailable_without_persistence_or_raw_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()
    raw_target = "private-investigation-target"
    logger = RecordingLogger()
    engine_created = False

    def engine_factory():
        nonlocal engine_created
        engine_created = True
        return RecordingEngine()

    monkeypatch.setattr(worker, "logger", logger)

    outcome = await worker.run_scan_task(
        {
            "job_id": raw_target,
            "settings": Settings(_env_file=None),
            "correlation_engine_factory": engine_factory,
        },
        "username",
        raw_target,
    )

    assert outcome.state is scan_state.UNAVAILABLE
    assert outcome.code == "all_adapters_unavailable"
    assert outcome.discovered_count == 0
    assert engine_created is False
    assert raw_target not in repr(outcome)
    assert all(
        raw_target not in message and raw_target not in repr(context)
        for message, context in logger.records
    )


@pytest.mark.asyncio
async def test_worker_uses_ip_model_and_reports_no_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()
    observed_target_types: list[type] = []

    async def run(self, target):
        observed_target_types.append(type(target))
        return {}

    monkeypatch.setattr(ShodanAdapter, "run", run)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    outcome = await worker.run_scan_task(
        {
            "job_id": "job-ip-empty",
            "settings": Settings(
                SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
            ),
        },
        "ip",
        "203.0.113.10",
    )

    assert outcome.state is scan_state.NO_RESULTS
    assert outcome.code == "no_findings"
    assert observed_target_types == [IPEntity]


@pytest.mark.asyncio
async def test_worker_redacts_and_persists_only_real_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()
    engine = RecordingEngine()

    async def run(self, target):
        return {"hostnames": ["host.example.com"]}

    def parse(self, raw_output):
        return [
            DomainEntity(
                value="host.example.com",
                metadata={"Password": "secret", "source": "shodan"},
            )
        ]

    monkeypatch.setattr(ShodanAdapter, "run", run)
    monkeypatch.setattr(ShodanAdapter, "parse", parse)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    outcome = await worker.run_scan_task(
        {
            "job_id": "job-success",
            "settings": Settings(
                SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
            ),
            "correlation_engine_factory": lambda: engine,
        },
        "ip",
        "203.0.113.10",
    )

    assert outcome.state is scan_state.SUCCEEDED
    assert outcome.code == "persisted"
    assert outcome.discovered_count == 1
    assert engine.added[0].metadata == {
        "Password": "[REDACTED]",
        "source": "shodan",
    }
    assert engine.source == IPEntity(value="203.0.113.10")
    assert engine.correlated is True
    assert engine.closed is True


@pytest.mark.asyncio
async def test_worker_never_reports_success_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()
    engine = RecordingEngine(fail_add=True)

    async def run(self, target):
        return {"hostnames": ["host.example.com"]}

    monkeypatch.setattr(ShodanAdapter, "run", run)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    outcome = await worker.run_scan_task(
        {
            "job_id": "job-persistence-failure",
            "settings": Settings(
                SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
            ),
            "correlation_engine_factory": lambda: engine,
        },
        "ip",
        "203.0.113.10",
    )

    assert outcome.state is scan_state.FAILED
    assert outcome.code == "persistence_failed"
    assert outcome.successful is False
    assert engine.closed is True


@pytest.mark.asyncio
async def test_worker_adapter_failure_skips_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()
    engine_created = False

    async def run(self, target):
        raise ValueError("malformed upstream response")

    def engine_factory():
        nonlocal engine_created
        engine_created = True
        return RecordingEngine()

    monkeypatch.setattr(ShodanAdapter, "run", run)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    outcome = await worker.run_scan_task(
        {
            "job_id": "job-adapter-failure",
            "settings": Settings(
                SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
            ),
            "correlation_engine_factory": engine_factory,
        },
        "ip",
        "203.0.113.10",
    )

    assert outcome.state is scan_state.FAILED
    assert outcome.code == "adapter_failed"
    assert outcome.successful is False
    assert engine_created is False


@pytest.mark.asyncio
async def test_worker_preserves_retryable_failure_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_state = _worker_api()

    async def run(self, target):
        raise RetryableAdapterError("temporary upstream failure")

    monkeypatch.setattr(ShodanAdapter, "run", run)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)
    monkeypatch.setattr(
        ShodanAdapter, "get_retry_delay", lambda self, attempt: 0
    )

    outcome = await worker.run_scan_task(
        {
            "job_id": "job-retryable-failure",
            "settings": Settings(
                SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
            ),
        },
        "ip",
        "203.0.113.10",
    )

    assert outcome.state is scan_state.RETRYABLE_FAILURE
    assert outcome.code == "adapter_retry_exhausted"
    shodan_outcome = next(
        item for item in outcome.adapter_outcomes if item.adapter_id == "shodan"
    )
    assert shodan_outcome.attempts == 3


@pytest.mark.asyncio
async def test_worker_rejects_unknown_target_type_without_fallback() -> None:
    scan_state = _worker_api()

    outcome = await worker.run_scan_task(
        {"job_id": "job-unsupported"}, "not-a-target-type", "anything"
    )

    assert outcome.state is scan_state.FAILED
    assert outcome.code == "unsupported_target_type"
    assert outcome.adapter_outcomes == ()
