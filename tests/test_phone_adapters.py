from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.phone import PhoneInfogaAdapter
from app.schemas.entities import EmailEntity, PhoneEntity
from app.schemas.outcomes import AdapterState


@pytest.mark.asyncio
async def test_phoneinfoga_is_unavailable() -> None:
    adapter = PhoneInfogaAdapter()
    target = PhoneEntity(value="+1234567890")
    assert adapter.validate(target) is True
    assert adapter.validate(EmailEntity(value="test@example.com")) is False
    with patch("app.adapters.phone.run_cli_command", new_callable=AsyncMock) as run:
        outcome = await adapter.execute(target)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    run.assert_not_awaited()
