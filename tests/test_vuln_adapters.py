from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.vuln import NucleiAdapter, SearchSploitAdapter, VulnersAdapter
from app.schemas.entities import CVEEntity, DomainEntity, IPEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "target"),
    [
        (NucleiAdapter, DomainEntity(value="example.com")),
        (SearchSploitAdapter, IPEntity(value="203.0.113.10", metadata={"ports": ["80"]})),
        (VulnersAdapter, CVEEntity(value="CVE-2023-1234")),
    ],
)
async def test_vulnerability_adapters_are_unavailable(adapter_type, target) -> None:
    adapter = adapter_type()
    with patch.object(adapter, "run", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
