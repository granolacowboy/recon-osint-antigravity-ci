from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.corporate import SpiderFootAdapter
from app.schemas.entities import CompanyEntity, DomainEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState


@pytest.mark.asyncio
@patch("app.adapters.corporate.run_cli_command", new_callable=AsyncMock)
async def test_spiderfoot_adapter(mock_run: AsyncMock) -> None:
    adapter = SpiderFootAdapter()
    valid_target = CompanyEntity(value="Example Inc")

    assert adapter.validate(valid_target) is True

    outcome = await adapter.execute(valid_target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {"results": [{"type": "domain", "val": "example.com"}]}
    )
    assert len(parsed) == 1
    assert isinstance(parsed[0], DomainEntity)
    assert parsed[0].value == "example.com"
