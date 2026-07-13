import asyncio
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from typing import Any

from app.core.logging import logger
from app.core.config import settings


def _validate_argv(argv: object) -> list[str]:
    if not isinstance(argv, list):
        raise TypeError("argv must be a list of strings")
    if not argv:
        raise ValueError("argv must not be empty")
    if not all(isinstance(argument, str) for argument in argv):
        raise TypeError("every argv item must be a string")
    if not argv[0]:
        raise ValueError("argv[0] must not be empty")
    if any("\x00" in argument for argument in argv):
        raise ValueError("argv items must not contain NUL bytes")
    return argv


async def _wait_for_process_exit(process: Any, timeout: float = 2.0) -> None:
    if process.returncode is not None:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        if process.returncode is None:
            process.kill()
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout)
        except (asyncio.TimeoutError, ProcessLookupError):
            return


async def _terminate_process_tree(process: Any) -> None:
    """Terminate the spawned process and all of its descendants."""
    if process.returncode is not None:
        return

    if os.name == "nt":
        try:
            taskkill = await asyncio.create_subprocess_exec(
                "taskkill.exe",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await taskkill.communicate()
        except (FileNotFoundError, ProcessLookupError):
            if process.returncode is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    await _wait_for_process_exit(process)


async def _shielded_terminate(process: Any) -> None:
    cleanup = asyncio.create_task(_terminate_process_tree(process))
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        await cleanup


async def run_cli_command(
    argv: list[str],
    timeout: float | None = None,
    *,
    stdin: str | bytes | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> tuple[int, str, str]:
    """
    Execute a literal argv vector without a shell.

    Text or bytes may be supplied on standard input. Timeout and caller
    cancellation both terminate the complete process tree.
    Returns (returncode, stdout, stderr).
    """
    command = _validate_argv(argv)
    if timeout is None:
        timeout = settings.DEFAULT_TIMEOUT
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if stdin is not None and not isinstance(stdin, (str, bytes)):
        raise TypeError("stdin must be text, bytes, or None")

    stdin_bytes = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    process: Any | None = None
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    if cwd is None:
        temporary_directory = tempfile.TemporaryDirectory(prefix="recon-job-")
        working_directory = temporary_directory.name
    else:
        working_path = Path(cwd).resolve(strict=True)
        if not working_path.is_dir():
            raise ValueError("cwd must identify a directory")
        working_directory = str(working_path)

    subprocess_options: dict[str, Any] = {
        "stdin": (
            asyncio.subprocess.PIPE
            if stdin_bytes is not None
            else asyncio.subprocess.DEVNULL
        ),
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
        "cwd": working_directory,
    }
    if os.name == "nt":
        subprocess_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        subprocess_options["start_new_session"] = True

    try:
        creation_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                **subprocess_options,
            )
        )
        try:
            process = await asyncio.shield(creation_task)
        except asyncio.CancelledError:
            try:
                process = await creation_task
            except BaseException:
                process = None
            raise

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(input=stdin_bytes), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip() if stdout_bytes else ""
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip() if stderr_bytes else ""

        return process.returncode, stdout, stderr

    except asyncio.TimeoutError:
        logger.bind(executable=command[0], outcome_code="timeout").error(
            "command_execution_failed"
        )
        if process is not None:
            await _shielded_terminate(process)
        return 124, "", "Execution timed out."
    except asyncio.CancelledError:
        if process is not None:
            await _shielded_terminate(process)
        raise
    except Exception as exc:
        logger.bind(
            executable=command[0],
            outcome_code="execution_failed",
            error_type=type(exc).__name__,
        ).error("command_execution_failed")
        return 1, "", str(exc)
    finally:
        if temporary_directory is not None:
            temporary_directory.cleanup()
