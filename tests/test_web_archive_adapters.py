from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.web_archive import GauAdapter, WaybackurlsAdapter
from app.schemas.entities import DomainEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_type", [WaybackurlsAdapter, GauAdapter])
async def test_web_archive_cli_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    with patch("app.adapters.web_archive.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(DomainEntity(value="example.com"))
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
