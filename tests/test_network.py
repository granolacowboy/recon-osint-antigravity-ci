from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.network import MasscanAdapter, NaabuAdapter, NmapAdapter, RustScanAdapter
from app.schemas.entities import IPEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type", [NmapAdapter, MasscanAdapter, RustScanAdapter, NaabuAdapter]
)
async def test_active_network_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    with patch("app.adapters.network.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(IPEntity(value="203.0.113.10"))
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
