from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.metadata import FOCAAdapter, MetagoofilAdapter
from app.schemas.entities import DomainEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_type", [FOCAAdapter, MetagoofilAdapter])
async def test_metadata_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    with patch("app.adapters.metadata.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(DomainEntity(value="example.com"))
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
