from typing import Any, List

import pytest

from app.adapters.base import ToolAdapter
from app.core.config import Settings
from app.schemas.entities import TargetEntity, UsernameEntity
from app.schemas.outcomes import AdapterMetadata, AdapterOutcome, AdapterState


class DummyAdapter(ToolAdapter):
    metadata = AdapterMetadata(
        adapter_id="dummy",
        display_name="Dummy test adapter",
        target_types=("username",),
        passive=True,
        enabled=True,
        max_attempts=1,
    )

    def validate(self, target: TargetEntity) -> bool:
        return isinstance(target, UsernameEntity)

    async def run(self, target: TargetEntity) -> Any:
        return {"found": True, "username": target.value}

    def parse(self, raw_output: Any) -> List[TargetEntity]:
        if raw_output.get("found"):
            return [UsernameEntity(value=raw_output["username"])]
        return []

    def get_rate_limit(self) -> float:
        return 0


@pytest.mark.asyncio
async def test_dummy_adapter() -> None:
    adapter = DummyAdapter(config=Settings(_env_file=None))
    target = UsernameEntity(value="alice")

    assert adapter.validate(target) is True

    outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.SUCCEEDED
    assert outcome.attempts == 1
    assert len(outcome.findings) == 1
    assert outcome.findings[0].value == "alice"
    assert isinstance(outcome.findings[0], UsernameEntity)


def test_missing_methods() -> None:
    class BadAdapter(ToolAdapter):
        pass

    with pytest.raises(TypeError):
        BadAdapter()
