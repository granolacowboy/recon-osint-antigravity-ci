from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.username import BlackbirdAdapter, SherlockAdapter
from app.schemas.entities import EmailEntity, UsernameEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_type", [SherlockAdapter, BlackbirdAdapter])
async def test_username_cli_adapters_are_unavailable(adapter_type) -> None:
    adapter = adapter_type()
    target = UsernameEntity(value="testuser")
    assert adapter.validate(target) is True
    assert adapter.validate(EmailEntity(value="test@example.com")) is False
    with patch("app.adapters.username.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
