from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from app.utils import execution


class FakeProcess:
    def __init__(
        self,
        *,
        stdout: bytes = b"stdout\n",
        stderr: bytes = b"stderr\n",
        block: bool = False,
    ) -> None:
        self.pid = 4242
        self.returncode: int | None = None if block else 0
        self.stdout = stdout
        self.stderr = stderr
        self.block = block
        self.input: bytes | None = None
        self.killed = False

    async def communicate(self, input: bytes | None = None):
        self.input = input
        if self.block:
            await asyncio.Event().wait()
        return self.stdout, self.stderr

    async def wait(self) -> int:
        self.returncode = -9
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_argv",
    [
        "tool --flag",
        b"tool --flag",
        ("tool", "--flag"),
        [],
        ["tool", 123],
    ],
)
async def test_run_cli_command_rejects_non_argv_lists(
    invalid_argv: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create = pytest.fail
    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)

    with pytest.raises((TypeError, ValueError)):
        await execution.run_cli_command(invalid_argv)


@pytest.mark.asyncio
async def test_run_cli_command_preserves_arguments_and_text_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    invocation: dict[str, Any] = {}

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return process

    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)

    result = await execution.run_cli_command(
        ["tool", "value with spaces", "&&", "not-a-shell"],
        stdin="example.com\n",
    )

    assert result == (0, "stdout", "stderr")
    assert invocation["args"] == (
        "tool",
        "value with spaces",
        "&&",
        "not-a-shell",
    )
    assert "shell" not in invocation["kwargs"]
    assert invocation["kwargs"]["stdin"] is asyncio.subprocess.PIPE
    assert process.input == b"example.com\n"
    if os.name == "nt":
        assert invocation["kwargs"]["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        assert invocation["kwargs"]["start_new_session"] is True


@pytest.mark.asyncio
async def test_run_cli_command_accepts_bytes_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        return process

    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)

    await execution.run_cli_command(["tool"], stdin=b"raw\x00bytes")

    assert process.input == b"raw\x00bytes"


@pytest.mark.asyncio
async def test_run_cli_command_timeout_terminates_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(block=True)
    terminated: list[int] = []

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        return process

    async def terminate(proc: FakeProcess) -> None:
        terminated.append(proc.pid)
        proc.returncode = -9

    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        execution, "_terminate_process_tree", terminate, raising=False
    )

    result = await execution.run_cli_command(["tool"], timeout=0.001)

    assert result == (124, "", "Execution timed out.")
    assert terminated == [process.pid]


@pytest.mark.asyncio
async def test_run_cli_command_cancellation_terminates_tree_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(block=True)
    terminated: list[int] = []

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        return process

    async def terminate(proc: FakeProcess) -> None:
        terminated.append(proc.pid)
        proc.returncode = -9

    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        execution, "_terminate_process_tree", terminate, raising=False
    )
    task = asyncio.create_task(execution.run_cli_command(["tool"], timeout=30))
    await asyncio.sleep(0)

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert terminated == [process.pid]


@pytest.mark.asyncio
async def test_cancellation_during_spawn_still_terminates_created_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(block=True)
    spawn_started = asyncio.Event()
    release_spawn = asyncio.Event()
    terminated: list[int] = []

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        spawn_started.set()
        await release_spawn.wait()
        return process

    async def terminate(proc: FakeProcess) -> None:
        terminated.append(proc.pid)
        proc.returncode = -9

    monkeypatch.setattr(execution.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(execution, "_terminate_process_tree", terminate)
    task = asyncio.create_task(execution.run_cli_command(["tool"], timeout=30))
    await spawn_started.wait()

    task.cancel()
    release_spawn.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert terminated == [process.pid]


@pytest.mark.asyncio
async def test_run_cli_command_uses_and_removes_an_isolated_job_directory() -> None:
    returncode, stdout, stderr = await execution.run_cli_command(
        [sys.executable, "-c", "import os; print(os.getcwd())"]
    )

    job_directory = Path(stdout)
    assert returncode == 0
    assert stderr == ""
    assert job_directory.name.startswith("recon-job-")
    assert not job_directory.exists()
