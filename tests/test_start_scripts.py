from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
START_SH = ROOT / "scripts" / "start.sh"
START_PS1 = ROOT / "scripts" / "start.ps1"
START_CMD = ROOT / "scripts" / "start.cmd"
POWERSHELL = (
    shutil.which("pwsh")
    or shutil.which("powershell.exe")
    or shutil.which("powershell")
)


def _temporary_project(root: Path) -> Path:
    project = root / "project"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(START_SH, scripts / "start.sh")
    shutil.copy2(START_PS1, scripts / "start.ps1")
    shutil.copy2(START_CMD, scripts / "start.cmd")
    safe_environment = "REDIS_PASSWORD=test-only\nNEO4J_PASSWORD=test-only\n"
    (project / ".env").write_text(safe_environment, encoding="utf-8")
    (project / ".env.example").write_text(safe_environment, encoding="utf-8")
    return project


def _git_bash() -> str:
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        if git_bash.is_file():
            return str(git_bash)
    executable = shutil.which("bash")
    assert executable is not None, "bash is required to verify scripts/start.sh"
    return executable


def _run_shell_launcher(*launcher_args: str) -> list[list[str]]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        project = _temporary_project(temporary)
        fake_bin = temporary / "bin"
        fake_bin.mkdir()
        docker_log = temporary / "docker-shell.log"
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            """#!/usr/bin/env sh
{
  printf 'CALL'
  for argument do
    printf '\\t%s' "$argument"
  done
  printf '\\n'
} >> "$DOCKER_LOG"
""",
            encoding="utf-8",
        )
        fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IEXEC)

        environment = os.environ.copy()
        environment["DOCKER_LOG"] = docker_log.as_posix()
        environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
        completed = subprocess.run(
            [
                _git_bash(),
                (project / "scripts" / "start.sh").as_posix(),
                *launcher_args,
            ],
            cwd=project,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return [
            line.split("\t")[1:]
            for line in docker_log.read_text(encoding="utf-8").splitlines()
        ]


def _run_powershell_launcher(*launcher_args: str) -> list[list[str]]:
    assert POWERSHELL is not None
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        project = _temporary_project(temporary)
        docker_log = temporary / "docker-powershell.log"
        wrapper = temporary / "invoke-start.ps1"
        wrapper.write_text(
            """$ErrorActionPreference = "Stop"
function global:docker {
    $record = @($args) | ConvertTo-Json -Compress
    Add-Content -LiteralPath $env:DOCKER_LOG -Value $record -Encoding UTF8
    $global:LASTEXITCODE = 0
}
$launcherParameters = @{}
if ($env:START_DETACH -eq "1") {
    $launcherParameters["Detach"] = $true
}
if ($env:START_NO_BUILD -eq "1") {
    $launcherParameters["NoBuild"] = $true
}
& $env:START_SCRIPT @launcherParameters
exit $LASTEXITCODE
""",
            encoding="utf-8",
        )

        environment = os.environ.copy()
        environment["DOCKER_LOG"] = str(docker_log)
        environment["START_SCRIPT"] = str(project / "scripts" / "start.ps1")
        environment["START_DETACH"] = "1" if "-Detach" in launcher_args else "0"
        environment["START_NO_BUILD"] = "1" if "-NoBuild" in launcher_args else "0"
        completed = subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(wrapper),
            ],
            cwd=project,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return [
            json.loads(line.lstrip("\ufeff"))
            for line in docker_log.read_text(encoding="utf-8-sig").splitlines()
        ]


def test_shell_launcher_builds_by_default() -> None:
    assert _run_shell_launcher() == [
        ["compose", "run", "--rm", "--build", "--no-deps", "configcheck"],
        ["compose", "up", "--build"],
    ]


def test_shell_launcher_no_build_omits_all_compose_build_flags() -> None:
    calls = _run_shell_launcher("--detach", "--no-build")
    assert calls == [
        [
            "compose",
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "--abort-on-container-exit",
            "--exit-code-from",
            "configcheck",
            "configcheck",
        ],
        ["compose", "up", "--no-build", "--pull", "never", "--detach", "--wait"],
    ]
    assert all("--build" not in call for call in calls)


@unittest.skipUnless(POWERSHELL is not None, "PowerShell is not installed")
def test_powershell_launcher_builds_by_default() -> None:
    assert _run_powershell_launcher() == [
        ["compose", "run", "--rm", "--build", "--no-deps", "configcheck"],
        ["compose", "up", "--build"],
    ]


@unittest.skipUnless(POWERSHELL is not None, "PowerShell is not installed")
def test_powershell_launcher_no_build_omits_all_compose_build_flags() -> None:
    calls = _run_powershell_launcher("-Detach", "-NoBuild")
    assert calls == [
        [
            "compose",
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "--abort-on-container-exit",
            "--exit-code-from",
            "configcheck",
            "configcheck",
        ],
        ["compose", "up", "--no-build", "--pull", "never", "--detach", "--wait"],
    ]
    assert all("--build" not in call for call in calls)


def test_powershell_launcher_declares_no_build_parity() -> None:
    launcher = START_PS1.read_text(encoding="utf-8")
    assert "[switch]$NoBuild" in launcher
    assert '"--abort-on-container-exit"' in launcher
    assert '"--exit-code-from"' in launcher
    assert '$upArguments += @("--no-build", "--pull", "never")' in launcher


def _project_resources_exist(docker: str, project_name: str) -> bool:
    label = f"label=com.docker.compose.project={project_name}"
    commands = (
        [docker, "container", "ls", "--all", "--quiet", "--filter", label],
        [docker, "network", "ls", "--quiet", "--filter", label],
        [docker, "volume", "ls", "--quiet", "--filter", label],
    )
    return any(
        subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        ).stdout.strip()
        for command in commands
    )


def _image_state(docker: str, image: str) -> tuple[int, str]:
    completed = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Id}}|{{json .RepoDigests}}", image],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip()


def test_no_build_configcheck_compose_plan_never_builds_or_pulls() -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise unittest.SkipTest("Docker is not installed")
    compose_version = subprocess.run(
        [docker, "compose", "version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if compose_version.returncode != 0:
        raise unittest.SkipTest("Docker Compose is unavailable")
    docker_info = subprocess.run(
        [docker, "info"],
        text=True,
        capture_output=True,
        check=False,
    )
    if docker_info.returncode != 0:
        raise unittest.SkipTest("Docker daemon is unavailable")

    identifier = uuid.uuid4().hex
    image_tag = f"dry-run-{identifier}"
    project_name = f"recon-ci-dry-run-{identifier}"
    images = (
        f"recon-osint-api:{image_tag}",
        f"recon-osint-frontend:{image_tag}",
    )
    for image in images:
        inspect = subprocess.run(
            [docker, "image", "inspect", image],
            text=True,
            capture_output=True,
            check=False,
        )
        assert inspect.returncode != 0, f"dry-run tag unexpectedly exists: {image}"

    environment = os.environ.copy()
    environment.update(
        {
            "COMPOSE_ANSI": "never",
            "COMPOSE_PROJECT_NAME": project_name,
            "IMAGE_TAG": image_tag,
            "NO_COLOR": "1",
        }
    )
    compose_prefix = [
        docker,
        "compose",
        "--env-file",
        str(ROOT / ".env.example"),
    ]
    try:
        completed = subprocess.run(
            [
                *compose_prefix,
                "--dry-run",
                "up",
                "--no-build",
                "--pull",
                "never",
                "--no-deps",
                "--abort-on-container-exit",
                "--exit-code-from",
                "configcheck",
                "configcheck",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        output = completed.stdout + completed.stderr
        assert completed.returncode == 0, output
        assert "dry-run mode" in output.lower()
        assert "building" not in output.lower()
        assert "pulling" not in output.lower()
        for image in images:
            inspect = subprocess.run(
                [docker, "image", "inspect", image],
                text=True,
                capture_output=True,
                check=False,
            )
            assert inspect.returncode != 0, f"dry-run created an image: {image}"
    finally:
        if _project_resources_exist(docker, project_name):
            cleanup = subprocess.run(
                [
                    *compose_prefix,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    "--rmi",
                    "local",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert cleanup.returncode == 0, cleanup.stdout + cleanup.stderr


def test_preload_compose_plan_uses_example_env_without_side_effects() -> None:
    repository_env = ROOT / ".env"
    assert not repository_env.exists(), (
        "repository .env is user-owned state; remove it manually before this test"
    )

    docker = shutil.which("docker")
    if docker is None:
        raise unittest.SkipTest("Docker is not installed")
    compose_version = subprocess.run(
        [docker, "compose", "version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if compose_version.returncode != 0:
        raise unittest.SkipTest("Docker Compose is unavailable")
    docker_info = subprocess.run(
        [docker, "info"],
        text=True,
        capture_output=True,
        check=False,
    )
    if docker_info.returncode != 0:
        raise unittest.SkipTest("Docker daemon is unavailable")

    identifier = uuid.uuid4().hex
    image_tag = f"preload-dry-run-{identifier}"
    project_name = f"recon-ci-preload-dry-run-{identifier}"
    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    datastore_images = tuple(
        sorted(
            re.findall(
                r"(?m)^    image:\s*((?:redis|neo4j):[^\s]+@sha256:[0-9a-f]{64})\s*$",
                compose_text,
            )
        )
    )
    assert len(datastore_images) == 2
    datastore_state = {
        image: _image_state(docker, image) for image in datastore_images
    }
    app_images = (
        f"recon-osint-api:{image_tag}",
        f"recon-osint-frontend:{image_tag}",
    )
    assert all(_image_state(docker, image)[0] != 0 for image in app_images)
    assert not _project_resources_exist(docker, project_name)

    environment = os.environ.copy()
    environment.update(
        {
            "COMPOSE_ANSI": "never",
            "COMPOSE_PROJECT_NAME": project_name,
            "IMAGE_TAG": image_tag,
            "NO_COLOR": "1",
        }
    )
    compose_prefix = [
        docker,
        "compose",
        "--env-file",
        str(ROOT / ".env.example"),
    ]
    try:
        completed = subprocess.run(
            [
                *compose_prefix,
                "--dry-run",
                "pull",
                "--ignore-buildable",
                "redis",
                "neo4j",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        output = completed.stdout + completed.stderr
        assert completed.returncode == 0, output
        assert "building" not in output.lower()
        assert all(image.lower() in output.lower() for image in datastore_images)
        assert {
            image: _image_state(docker, image) for image in datastore_images
        } == datastore_state
        assert all(_image_state(docker, image)[0] != 0 for image in app_images)
        assert not _project_resources_exist(docker, project_name)
    finally:
        if _project_resources_exist(docker, project_name):
            cleanup = subprocess.run(
                [
                    *compose_prefix,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    "--rmi",
                    "local",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert cleanup.returncode == 0, cleanup.stdout + cleanup.stderr
        assert not repository_env.exists(), "Compose dry-run created repository .env"


def test_cmd_wrapper_forwards_all_arguments() -> None:
    wrapper = START_CMD.read_text(encoding="utf-8").lower()
    assert "start.ps1" in wrapper
    assert "%*" in wrapper
