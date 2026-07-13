from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.domain import AmassAdapter, AssetfinderAdapter
from app.schemas.entities import DomainEntity, EmailEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_type", [AmassAdapter, AssetfinderAdapter])
async def test_domain_cli_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    target = DomainEntity(value="example.com")
    assert adapter.validate(target) is True
    assert adapter.validate(EmailEntity(value="test@example.com")) is False

    with patch("app.adapters.domain.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)

    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()


def test_domain_parsers_accept_recorded_domains() -> None:
    assert [item.value for item in AmassAdapter().parse({"subdomains": ["www.example.com"]})] == [
        "www.example.com"
    ]
    assert [
        item.value
        for item in AssetfinderAdapter().parse({"subdomains": ["cdn.example.com"]})
    ] == ["cdn.example.com"]
