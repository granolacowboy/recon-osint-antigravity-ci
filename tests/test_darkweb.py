from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.darkweb import DarkdumpAdapter, OnionSearchAdapter, TorBotAdapter
from app.schemas.entities import DomainEntity, URLEntity, UsernameEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState


@pytest.mark.asyncio
@patch("app.adapters.darkweb.run_cli_command", new_callable=AsyncMock)
async def test_torbot_adapter(mock_run: AsyncMock) -> None:
    adapter = TorBotAdapter()
    valid_target = DomainEntity(value="test.onion")

    assert adapter.validate(valid_target) is True

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse({"scanned": True})
    assert len(parsed) == 1
    assert parsed[0].metadata["torbot_scanned"] is True


@pytest.mark.asyncio
@patch("app.adapters.darkweb.run_cli_command", new_callable=AsyncMock)
async def test_onionsearch_adapter(mock_run: AsyncMock) -> None:
    adapter = OnionSearchAdapter()
    valid_target = UsernameEntity(value="hacker")

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {"onion_urls": ["http://test.onion", "http://test2.onion"]}
    )
    assert len(parsed) == 2
    assert isinstance(parsed[0], URLEntity)


@pytest.mark.asyncio
@patch("app.adapters.darkweb.run_cli_command", new_callable=AsyncMock)
async def test_darkdump_adapter(mock_run: AsyncMock) -> None:
    adapter = DarkdumpAdapter()
    valid_target = UsernameEntity(value="hacker")

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse({"found": True})
    assert len(parsed) == 1
    assert parsed[0].metadata["darkdump_found"] is True
