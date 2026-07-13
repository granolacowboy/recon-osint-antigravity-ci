from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.social import CrossLinkedAdapter, OSINTgramAdapter, SocialAnalyzerAdapter
from app.schemas.entities import CompanyEntity, UsernameEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "target"),
    [
        (SocialAnalyzerAdapter, UsernameEntity(value="user1")),
        (OSINTgramAdapter, UsernameEntity(value="user1")),
        (CrossLinkedAdapter, CompanyEntity(value="Corp")),
    ],
)
async def test_fabricated_social_adapters_are_unavailable(adapter_type, target) -> None:
    adapter = adapter_type()
    with patch("app.adapters.social.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
