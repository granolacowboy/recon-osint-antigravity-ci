from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.username import BlackbirdAdapter, SherlockAdapter
from app.schemas.entities import UsernameEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState


@pytest.mark.asyncio
async def test_sherlock_adapter() -> None:
    adapter = SherlockAdapter()
    target = UsernameEntity(value="johndoe123")

    with patch(
        "app.adapters.username.run_cli_command", new_callable=AsyncMock
    ) as mock_run:
        outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {
            "urls": [
                "http://github.com/johndoe123",
                "http://twitter.com/johndoe123",
            ]
        }
    )
    assert [finding.value for finding in parsed] == [
        "http://github.com/johndoe123",
        "http://twitter.com/johndoe123",
    ]
    assert parsed[0].metadata["source"] == "sherlock"


@pytest.mark.asyncio
async def test_blackbird_adapter() -> None:
    adapter = BlackbirdAdapter()
    target = UsernameEntity(value="johndoe123")

    with patch(
        "app.adapters.username.run_cli_command", new_callable=AsyncMock
    ) as mock_run:
        outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {
            "urls": [
                "http://github.com/johndoe123",
                "http://example.com/johndoe123",
            ]
        }
    )
    assert [finding.value for finding in parsed] == [
        "http://github.com/johndoe123",
        "http://example.com/johndoe123",
    ]
    assert parsed[0].metadata["source"] == "blackbird"
