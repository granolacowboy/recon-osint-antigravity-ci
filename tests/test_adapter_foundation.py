from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.adapters.base import ToolAdapter
from app.core.config import Settings
from app.schemas.base import TargetEntity
from app.schemas.entities import DomainEntity, IPEntity, UsernameEntity


def _adapter_api():
    from app.adapters.registry import (
        ADAPTER_REGISTRY,
        TARGET_MODEL_REGISTRY,
        get_adapter_registrations,
    )
    from app.schemas.outcomes import (
        AdapterMetadata,
        AdapterState,
        RetryableAdapterError,
    )

    return (
        ADAPTER_REGISTRY,
        TARGET_MODEL_REGISTRY,
        get_adapter_registrations,
        AdapterMetadata,
        AdapterState,
        RetryableAdapterError,
    )


def _target_for(target_type: str) -> TargetEntity:
    values = {
        "username": "alice",
        "email": "alice@example.com",
        "phone": "+15551234567",
        "domain": "example.com",
        "ip": "203.0.113.10",
        "url": "https://example.com/resource",
        "company": "Example Company",
        "vulnerability": "Example vulnerability",
        "cve": "CVE-2025-1234",
        "repository": "https://example.com/repository.git",
        "cloud_storage": "example-bucket",
        "breach": "Example breach",
        "dark_web_forum": "Example forum",
    }
    _, target_models, _, _, _, _ = _adapter_api()
    return target_models[target_type](value=values[target_type])


def test_target_model_registry_maps_ip_to_ip_entity() -> None:
    _, target_models, _, _, _, _ = _adapter_api()

    assert target_models["ip"] is IPEntity
    assert target_models["domain"] is DomainEntity


def test_registry_explicitly_accounts_for_every_production_adapter() -> None:
    adapter_registry, _, _, _, _, _ = _adapter_api()
    registered_types = {entry.adapter_type for entry in adapter_registry.values()}
    production_types = {
        adapter_type
        for adapter_type in ToolAdapter.__subclasses__()
        if adapter_type.__module__.startswith("app.adapters.")
    }

    assert registered_types == production_types
    assert len(registered_types) == len(adapter_registry)


def test_only_shodan_can_be_enabled_and_requires_a_real_key() -> None:
    adapter_registry, _, _, _, _, _ = _adapter_api()
    placeholder_settings = Settings(SHODAN_API_KEY="mock", _env_file=None)
    configured_settings = Settings(
        SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
    )

    placeholder_enabled = {
        adapter_id
        for adapter_id, entry in adapter_registry.items()
        if entry.metadata_for(placeholder_settings).enabled
    }
    configured_enabled = {
        adapter_id
        for adapter_id, entry in adapter_registry.items()
        if entry.metadata_for(configured_settings).enabled
    }

    assert placeholder_enabled == set()
    assert configured_enabled == {"shodan"}


@pytest.mark.parametrize(
    "placeholder_key",
    [
        "mock-key",
        "placeholder-value",
        "changeme123",
        "your-shodan-api-key",
        "test-key",
    ],
)
def test_shodan_rejects_common_placeholder_key_variants(
    placeholder_key: str,
) -> None:
    adapter_registry, _, _, _, _, _ = _adapter_api()
    config = Settings(SHODAN_API_KEY=placeholder_key, _env_file=None)

    assert adapter_registry["shodan"].metadata_for(config).enabled is False


@pytest.mark.asyncio
async def test_disabled_adapters_report_unavailable_without_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter_registry, _, _, _, adapter_state, _ = _adapter_api()
    configured_settings = Settings(
        SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
    )

    for adapter_id, entry in adapter_registry.items():
        if adapter_id == "shodan":
            continue
        adapter = entry.create(configured_settings)
        run = AsyncMock(side_effect=AssertionError("disabled adapter executed"))
        monkeypatch.setattr(adapter, "run", run)
        target_type = entry.metadata.target_types[0]

        outcome = await adapter.execute(_target_for(target_type))

        assert outcome.state is adapter_state.UNAVAILABLE
        assert outcome.findings == ()
        run.assert_not_awaited()


@pytest.mark.asyncio
async def test_shodan_uses_params_and_reports_real_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, registrations_for, _, adapter_state, _ = _adapter_api()
    settings = Settings(
        SHODAN_API_KEY="test-real-looking-shodan-key", _env_file=None
    )
    registration = next(
        entry for entry in registrations_for("ip") if entry.adapter_id == "shodan"
    )
    adapter = registration.create(settings)
    fetch = AsyncMock(
        return_value={
            "hostnames": ["host.example.com"],
            "ports": [443],
            "org": "Example Org",
        }
    )
    monkeypatch.setattr("app.adapters.ip.fetch_json", fetch)

    outcome = await adapter.execute(IPEntity(value="203.0.113.10"))

    assert outcome.state is adapter_state.SUCCEEDED
    assert outcome.attempts == 1
    assert [finding.value for finding in outcome.findings] == ["host.example.com"]
    request_url = fetch.await_args.args[0]
    assert "test-real-looking-shodan-key" not in request_url
    assert fetch.await_args.kwargs["params"] == {
        "key": "test-real-looking-shodan-key"
    }


@pytest.mark.asyncio
async def test_successful_empty_parse_is_no_results() -> None:
    _, _, _, adapter_metadata, adapter_state, _ = _adapter_api()

    class EmptyAdapter(ToolAdapter):
        metadata = adapter_metadata(
            adapter_id="test-empty",
            display_name="Empty test adapter",
            target_types=("username",),
            passive=True,
            enabled=True,
            max_attempts=3,
        )

        def validate(self, target: TargetEntity) -> bool:
            return isinstance(target, UsernameEntity)

        async def run(self, target: TargetEntity):
            return {"results": []}

        def parse(self, raw_output):
            return []

    outcome = await EmptyAdapter(
        config=Settings(_env_file=None)
    ).execute(UsernameEntity(value="alice"))

    assert outcome.state is adapter_state.NO_RESULTS
    assert outcome.findings == ()
    assert outcome.attempts == 1


@pytest.mark.asyncio
async def test_retryable_failure_retries_then_succeeds() -> None:
    _, _, _, adapter_metadata, adapter_state, retryable_error = _adapter_api()

    class FlakyAdapter(ToolAdapter):
        metadata = adapter_metadata(
            adapter_id="test-flaky",
            display_name="Flaky test adapter",
            target_types=("username",),
            passive=True,
            enabled=True,
            max_attempts=3,
        )

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.calls = 0

        def validate(self, target: TargetEntity) -> bool:
            return isinstance(target, UsernameEntity)

        async def run(self, target: TargetEntity):
            self.calls += 1
            if self.calls < 3:
                raise retryable_error("temporary upstream failure")
            return {"username": target.value}

        def parse(self, raw_output):
            return [UsernameEntity(value=raw_output["username"])]

        def get_retry_delay(self, attempt: int) -> float:
            return 0

    adapter = FlakyAdapter(config=Settings(_env_file=None))

    outcome = await adapter.execute(UsernameEntity(value="alice"))

    assert outcome.state is adapter_state.SUCCEEDED
    assert outcome.attempts == 3
    assert adapter.calls == 3


@pytest.mark.asyncio
async def test_exhausted_retryable_failure_is_not_empty_success() -> None:
    _, _, _, adapter_metadata, adapter_state, retryable_error = _adapter_api()

    class FailingAdapter(ToolAdapter):
        metadata = adapter_metadata(
            adapter_id="test-failing",
            display_name="Failing test adapter",
            target_types=("username",),
            passive=True,
            enabled=True,
            max_attempts=3,
        )

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.calls = 0

        def validate(self, target: TargetEntity) -> bool:
            return isinstance(target, UsernameEntity)

        async def run(self, target: TargetEntity):
            self.calls += 1
            raise retryable_error("temporary upstream failure")

        def parse(self, raw_output):
            raise AssertionError("parse must not run after a failed request")

        def get_retry_delay(self, attempt: int) -> float:
            return 0

    adapter = FailingAdapter(config=Settings(_env_file=None))

    outcome = await adapter.execute(UsernameEntity(value="alice"))

    assert outcome.state is adapter_state.RETRYABLE_FAILURE
    assert outcome.findings == ()
    assert outcome.attempts == 3
    assert adapter.calls == 3


@pytest.mark.asyncio
async def test_non_retryable_failure_is_failed_once() -> None:
    _, _, _, adapter_metadata, adapter_state, _ = _adapter_api()

    class BrokenAdapter(ToolAdapter):
        metadata = adapter_metadata(
            adapter_id="test-broken",
            display_name="Broken test adapter",
            target_types=("username",),
            passive=True,
            enabled=True,
            max_attempts=3,
        )

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.calls = 0

        def validate(self, target: TargetEntity) -> bool:
            return isinstance(target, UsernameEntity)

        async def run(self, target: TargetEntity):
            self.calls += 1
            raise ValueError("invalid response")

        def parse(self, raw_output):
            raise AssertionError("parse must not run after a failed request")

    adapter = BrokenAdapter(config=Settings(_env_file=None))

    outcome = await adapter.execute(UsernameEntity(value="alice"))

    assert outcome.state is adapter_state.FAILED
    assert outcome.findings == ()
    assert outcome.attempts == 1
    assert adapter.calls == 1
