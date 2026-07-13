from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.email import MosintAdapter, TheHarvesterAdapter
from app.schemas.entities import DomainEntity, EmailEntity, UsernameEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
async def test_email_cli_adapters_are_unavailable() -> None:
    cases = [
        (MosintAdapter(), EmailEntity(value="test@example.com")),
        (TheHarvesterAdapter(), DomainEntity(value="example.com")),
    ]
    with patch("app.adapters.email.run_cli_command", new_callable=AsyncMock) as run:
        outcomes = [await adapter.execute(target) for adapter, target in cases]

    assert all(outcome.state is AdapterState.UNAVAILABLE for outcome in outcomes)
    assert all(outcome.findings == () for outcome in outcomes)
    run.assert_not_awaited()
    assert MosintAdapter().validate(UsernameEntity(value="testuser")) is False


def test_email_parsers_accept_recorded_provider_data() -> None:
    mosint = MosintAdapter().parse(
        {"domain": "example.com", "breaches": ["breach-a", "breach-b"]}
    )
    harvested = TheHarvesterAdapter().parse(
        {"emails": ["admin@example.com", "support@example.com"]}
    )
    assert mosint[0].value == "example.com"
    assert len(mosint[0].metadata["breaches"]) == 2
    assert [item.value for item in harvested] == [
        "admin@example.com",
        "support@example.com",
    ]
