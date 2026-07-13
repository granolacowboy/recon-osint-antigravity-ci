from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.cloud import CloudEnumAdapter, GitReconAdapter, TruffleHogAdapter
from app.schemas.entities import CompanyEntity, RepositoryEntity, UsernameEntity
from app.schemas.outcomes import AdapterOutcome, AdapterState


@pytest.mark.asyncio
async def test_cloudenum_adapter() -> None:
    adapter = CloudEnumAdapter()
    target = CompanyEntity(value="testcompany")

    with patch(
        "app.adapters.cloud.run_cli_command", new_callable=AsyncMock
    ) as mock_run:
        outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse({"aws": {"open": ["test-bucket"]}})
    assert len(parsed) == 1
    assert parsed[0].value == "test-bucket"
    assert parsed[0].metadata["provider"] == "aws"
    assert parsed[0].metadata["access"] == "open"


@pytest.mark.asyncio
async def test_trufflehog_adapter() -> None:
    adapter = TruffleHogAdapter()
    target = RepositoryEntity(value="https://github.com/test/repo")

    with patch(
        "app.adapters.cloud.run_cli_command", new_callable=AsyncMock
    ) as mock_run:
        outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_run.assert_not_awaited()

    parsed = adapter.parse(
        {"secrets": [{"DetectorName": "AWS", "DecoderName": "aws-key"}]}
    )
    assert len(parsed) == 1
    assert parsed[0].value == "AWS"
    assert parsed[0].metadata["file"] == "aws-key"
    assert parsed[0].metadata["redacted_secret"] == "***"


@pytest.mark.asyncio
async def test_gitrecon_adapter() -> None:
    adapter = GitReconAdapter()
    target = UsernameEntity(value="testuser")

    with patch("app.adapters.cloud.fetch_json", new_callable=AsyncMock) as mock_fetch:
        outcome = await adapter.execute(target)

    assert isinstance(outcome, AdapterOutcome)
    assert outcome.state is AdapterState.UNAVAILABLE
    assert outcome.findings == ()
    mock_fetch.assert_not_awaited()

    parsed = adapter.parse(
        [
            {
                "html_url": "https://github.com/testuser/repo",
                "description": "desc",
                "fork": False,
            }
        ]
    )
    assert len(parsed) == 1
    assert parsed[0].value == "https://github.com/testuser/repo"
    assert parsed[0].metadata["description"] == "desc"
