import pytest

from app.schemas.outcomes import ScanOutcome, ScanState
from app.worker import WorkerSettings, run_case_scan_task, run_scan_task


def test_worker_settings() -> None:
    assert WorkerSettings.functions == [run_case_scan_task]
    assert run_scan_task not in WorkerSettings.functions


@pytest.mark.asyncio
async def test_run_scan_task_returns_truthful_unavailable_outcome() -> None:
    outcome = await run_scan_task({}, "username", "testuser")
    assert isinstance(outcome, ScanOutcome)
    assert outcome.state is ScanState.UNAVAILABLE
    assert outcome.code == "all_adapters_unavailable"
    assert "testuser" not in repr(outcome)
