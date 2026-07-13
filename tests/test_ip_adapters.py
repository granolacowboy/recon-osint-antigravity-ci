from unittest.mock import AsyncMock, patch
import json
from pathlib import Path

import pytest

from app.adapters.ip import CensysAdapter, ShodanAdapter
from app.core.config import Settings
from app.schemas.entities import DomainEntity, IPEntity
from app.schemas.outcomes import AdapterState, HTTPStatusAdapterError


@pytest.mark.asyncio
async def test_shodan_adapter_returns_recorded_findings() -> None:
    adapter = ShodanAdapter(
        config=Settings(SHODAN_API_KEY="real-looking-key", _env_file=None)
    )
    with patch("app.adapters.ip.fetch_json", new_callable=AsyncMock) as fetch:
        fetch.return_value = json.loads(
            (Path(__file__).parent / "fixtures" / "shodan_host.json").read_text(
                encoding="utf-8"
            )
        )
        outcome = await adapter.execute(IPEntity(value="203.0.113.10"))

    assert outcome.state is AdapterState.SUCCEEDED
    assert isinstance(outcome.findings[0], DomainEntity)
    assert outcome.findings[0].metadata["ports"] == [443]
    assert fetch.await_args.kwargs["params"] == {"key": "real-looking-key"}


@pytest.mark.asyncio
async def test_censys_adapter_is_unavailable_and_not_executed() -> None:
    adapter = CensysAdapter()
    with patch.object(adapter, "run", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(IPEntity(value="203.0.113.10"))
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "state", "code"),
    [
        (404, AdapterState.NO_RESULTS, "provider_not_found"),
        (401, AdapterState.UNAVAILABLE, "provider_authentication_failed"),
        (403, AdapterState.UNAVAILABLE, "provider_authentication_failed"),
    ],
)
async def test_shodan_preserves_not_found_and_authentication_outcomes(
    status_code, state, code
) -> None:
    adapter = ShodanAdapter(
        config=Settings(SHODAN_API_KEY="real-looking-key", _env_file=None)
    )
    with patch("app.adapters.ip.fetch_json", new_callable=AsyncMock) as fetch:
        fetch.side_effect = HTTPStatusAdapterError(status_code)
        outcome = await adapter.execute(IPEntity(value="203.0.113.10"))

    assert outcome.state is state
    assert outcome.code == code
