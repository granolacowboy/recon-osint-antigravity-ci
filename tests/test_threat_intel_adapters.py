from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.threat_intel import MISPAdapter, OpenCTIAdapter, YetiAdapter
from app.schemas.entities import DomainEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_type", [MISPAdapter, OpenCTIAdapter, YetiAdapter])
async def test_fabricated_threat_intel_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    with patch.object(adapter, "run", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(DomainEntity(value="example.com"))
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
