from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.breach import DeHashedAdapter, H8mailAdapter
from app.schemas.entities import EmailEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState


@pytest.mark.asyncio
@patch("app.adapters.breach.fetch_json", new_callable=AsyncMock)
async def test_dehashed_adapter(mock_fetch: AsyncMock) -> None:
    adapter = DeHashedAdapter()
    valid_target = EmailEntity(value="alice@example.com")

    assert adapter.validate(valid_target) is True

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_fetch.assert_not_awaited()

    parsed = adapter.parse(
        {
            "entries": [
                {
                    "email": "alice@example.com",
                    "database_name": "db1",
                    "password": "pass",
                }
            ]
        }
    )
    assert len(parsed) == 1
    assert parsed[0].value == "alice@example.com"
    assert parsed[0].metadata["password"] == "pass"


@pytest.mark.asyncio
@patch("app.adapters.breach.run_cli_command", new_callable=AsyncMock)
async def test_h8mail_adapter(mock_run: AsyncMock) -> None:
    adapter = H8mailAdapter()
    valid_target = EmailEntity(value="alice@example.com")

    assert adapter.validate(valid_target) is True

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {
            "results": [
                {
                    "email": "alice@example.com",
                    "breaches": ["db1"],
                    "passwords_found": 1,
                    "cleartext_passwords": ["pass"],
                }
            ]
        }
    )
    assert len(parsed) == 1
    assert parsed[0].value == "alice@example.com"
    assert "db1" in parsed[0].metadata["breaches"]
