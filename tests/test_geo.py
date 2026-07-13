from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.geo import CreepyAdapter, ExifToolAdapter, GeoGuessrResolverAdapter
from app.schemas.entities import URLEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type", [ExifToolAdapter, GeoGuessrResolverAdapter, CreepyAdapter]
)
async def test_geo_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    target = URLEntity(value="https://example.com/image.jpg")
    with patch("app.adapters.geo.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
