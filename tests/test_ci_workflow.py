from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RUNBOOK_PATH = ROOT / "docs" / "runbooks" / "self-hosted-ci.md"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
BASELINE_JOBS = ("backend", "frontend", "integration", "containers")
SELF_HOSTED_SELECTOR = "[self-hosted, Linux, X64, recon-readiness]"
CONCURRENCY_GROUP = "recon-readiness-self-hosted"
OWNER_AND_FORK_GUARD = (
    "github.actor == github.repository_owner && "
    "github.triggering_actor == github.repository_owner && "
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)


def _job_block(job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        WORKFLOW,
    )
    assert match is not None, f"missing {job_name!r} job"
    return match.group("body")


def _step_blocks(job_block: str) -> list[str]:
    return re.findall(r"(?ms)^      - name: .*?(?=^      - name: |\Z)", job_block)


def test_events_and_permissions_are_minimal() -> None:
    trigger_block = WORKFLOW.split("\npermissions:", maxsplit=1)[0]
    assert re.search(r"(?m)^  pull_request:\s*$", trigger_block)
    assert "pull_request_target:" not in trigger_block

    push = re.search(
        r"(?ms)^  push:\n(?P<body>.*?)(?=^  [A-Za-z_][A-Za-z0-9_-]*:\s*$|\Z)",
        trigger_block,
    )
    assert push is not None, "missing push event"
    branches = [
        value.strip("'\"")
        for value in re.findall(r"(?m)^      -\s+(.+?)\s*$", push.group("body"))
    ]
    assert branches == ["main"]

    permissions = re.search(
        r"(?ms)^permissions:\n(?P<body>(?:  [^\n]+\n?)+)", WORKFLOW
    )
    assert permissions is not None
    assert permissions.group("body").strip() == "contents: read"


def test_workflow_runs_are_repository_globally_serialized() -> None:
    concurrency = re.search(
        r"(?ms)^concurrency:\n(?P<body>(?:  [^\n]+\n?)+)", WORKFLOW
    )
    assert concurrency is not None
    assert concurrency.group("body").splitlines() == [
        f"  group: {CONCURRENCY_GROUP}",
        "  cancel-in-progress: false",
    ]


def test_baseline_jobs_use_the_dedicated_self_hosted_runner() -> None:
    jobs_section = WORKFLOW.split("\njobs:\n", maxsplit=1)[1]
    job_names = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs_section)
    assert tuple(job_names) == BASELINE_JOBS

    assert "ubuntu-latest" not in WORKFLOW
    for job_name in BASELINE_JOBS:
        runs_on = re.findall(
            r"(?m)^    runs-on:\s*(.+?)\s*$", _job_block(job_name)
        )
        assert runs_on == [SELF_HOSTED_SELECTOR], job_name


def test_self_hosted_jobs_require_owner_and_reject_fork_pull_requests() -> None:
    for job_name in BASELINE_JOBS:
        guards = re.findall(r"(?m)^    if:\s*(.+?)\s*$", _job_block(job_name))
        assert guards == [OWNER_AND_FORK_GUARD], job_name


def test_actions_are_sha_pinned_without_artifact_or_cache_actions() -> None:
    action_refs = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", WORKFLOW)
    assert action_refs, "workflow must retain its action-backed gates"

    unpinned = [
        ref
        for ref in action_refs
        if re.fullmatch(r"[^@\s]+@[0-9a-fA-F]{40}", ref) is None
    ]
    assert unpinned == []

    repositories = {ref.partition("@")[0].lower() for ref in action_refs}
    prohibited = {
        "actions/cache",
        "actions/download-artifact",
        "actions/upload-artifact",
    }
    assert repositories.isdisjoint(prohibited)
    assert re.search(r"(?m)^\s+cache:\s*", WORKFLOW) is None
    assert "cache-dependency-path:" not in WORKFLOW


def test_security_actions_do_not_upload_or_cache_scan_state() -> None:
    steps = [step for job in BASELINE_JOBS for step in _step_blocks(_job_block(job))]
    sbom_steps = [step for step in steps if "uses: anchore/sbom-action@" in step]
    scan_steps = [step for step in steps if "uses: anchore/scan-action@" in step]

    assert len(sbom_steps) == 2
    assert all(
        re.search(r"(?m)^          upload-artifact:\s*false\s*$", step)
        for step in sbom_steps
    )
    assert len(scan_steps) == 2
    assert all(
        re.search(r"(?m)^          cache-db:\s*false\s*$", step)
        for step in scan_steps
    )


def test_docker_jobs_are_unique_and_always_remove_state() -> None:
    project_names: dict[str, str] = {}
    for job_name in ("integration", "containers"):
        job = _job_block(job_name)
        values = re.findall(
            r"(?m)^      COMPOSE_PROJECT_NAME:\s*(.+?)\s*$", job
        )
        assert len(values) == 1, job_name
        project_name = values[0].strip("'\"")
        assert "${{ github.run_id }}" in project_name
        assert "${{ github.run_attempt }}" in project_name
        assert job_name in project_name
        project_names[job_name] = project_name

        teardown_steps = [
            step
            for step in _step_blocks(job)
            if "if: always()" in step and "docker compose" in step and "down" in step
        ]
        assert len(teardown_steps) == 1, job_name
        normalized = re.sub(r"\s+", " ", teardown_steps[0])
        assert "down --volumes --remove-orphans" in normalized

    assert len(set(project_names.values())) == len(project_names)


def test_container_images_are_run_unique_and_unconditionally_removed() -> None:
    job = _job_block("containers")
    image_tags = re.findall(r"(?m)^      IMAGE_TAG:\s*(.+?)\s*$", job)
    assert len(image_tags) == 1
    image_tag = image_tags[0].strip("'\"")
    assert "${{ github.run_id }}" in image_tag
    assert "${{ github.run_attempt }}" in image_tag

    normalized = re.sub(r"\s+", " ", job)
    for image_name in ("recon-osint-api", "recon-osint-frontend"):
        shell_image = f'{image_name}:${{IMAGE_TAG}}'
        action_image = f"image: {image_name}:" + "${{ env.IMAGE_TAG }}"
        assert f'--tag "{shell_image}"' in normalized
        assert normalized.count(action_image) == 2

    assert normalized.count("docker build --no-cache") == 1
    assert "docker build --file frontend/Dockerfile --no-cache" in normalized

    steps = _step_blocks(job)
    scan_indices = [
        index for index, step in enumerate(steps) if "uses: anchore/scan-action@" in step
    ]
    launcher_indices = [
        index
        for index, step in enumerate(steps)
        if "bash ./scripts/start.sh --detach --no-build" in step
    ]
    preload_indices = [
        index
        for index, step in enumerate(steps)
        if "docker compose --env-file .env.example pull --ignore-buildable redis neo4j"
        in step
    ]
    assert len(scan_indices) == 2
    assert len(preload_indices) == 1
    assert len(launcher_indices) == 1
    assert max(scan_indices) < preload_indices[0] < launcher_indices[0]

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "image: recon-osint-api:${IMAGE_TAG:-local}" in compose
    assert "image: recon-osint-frontend:${IMAGE_TAG:-local}" in compose
    for service_name, image_name in (("redis", "redis"), ("neo4j", "neo4j")):
        service = re.search(
            rf"(?ms)^  {service_name}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            compose,
        )
        assert service is not None
        assert re.search(
            rf"(?m)^    image:\s*{image_name}:[^@\s]+@sha256:[0-9a-f]{{64}}\s*$",
            service.group("body"),
        )

    shell_source = (ROOT / "scripts" / "start.sh").read_text(encoding="utf-8")
    shell_launcher = re.sub(r"\s+", " ", shell_source.replace("\\\n", " "))
    assert (
        "set -- compose up --no-build --pull never --no-deps "
        "--abort-on-container-exit --exit-code-from configcheck configcheck"
    ) in shell_launcher

    cleanup_steps = [
        step
        for step in _step_blocks(job)
        if "if: always()" in step and "docker compose" in step and "down" in step
    ]
    assert len(cleanup_steps) == 1
    cleanup = re.sub(r"\s+", " ", cleanup_steps[0])
    compose = "docker compose down --volumes --remove-orphans"
    api_remove = 'docker image rm --force "recon-osint-api:${IMAGE_TAG}"'
    frontend_remove = 'docker image rm --force "recon-osint-frontend:${IMAGE_TAG}"'
    assert cleanup.index(compose) < cleanup.index(api_remove) < cleanup.index(
        frontend_remove
    )
    assert f"{compose} || cleanup_status=$?" in cleanup
    assert cleanup.count('if [ "$cleanup_status" -eq 0 ]; then') == 2
    assert cleanup.count("cleanup_status=$image_status") == 2
    assert 'exit "$cleanup_status"' in cleanup


def test_critical_quality_and_acceptance_gates_remain() -> None:
    normalized = re.sub(r"\s+", " ", WORKFLOW)
    required_fragments = (
        "python -m pip install --requirement requirements-dev.txt",
        "python -m pip check",
        "python -m pip_audit --requirement requirements.txt --progress-spinner off",
        "python -m pytest -q -p no:cacheprovider",
        "python scripts/export_openapi.py",
        "git diff --exit-code -- frontend/openapi.json",
        "npm ci --no-audit --no-fund",
        "npm audit --omit=dev --audit-level=high",
        "npm run lint",
        "npm run generate:api",
        "git diff --exit-code -- src/api/schema.d.ts",
        "npm run typecheck:api",
        "npm run test",
        "npm run build",
        "up --detach --wait redis neo4j",
        "-m integration tests/test_real_platform_integration.py",
        "docker compose --env-file .env.example config --quiet",
        "docker build --check .",
        'docker build --no-cache --target runtime --tag "recon-osint-api:${IMAGE_TAG}" .',
        "bash ./scripts/start.sh --detach --no-build",
        "curl --fail --silent http://127.0.0.1:8000/health/ready",
        "curl --fail --silent http://127.0.0.1:4173/healthz",
        "docker compose exec -T api id -u",
        "docker compose exec -T worker id -u",
        "docker compose exec -T frontend id -u",
        "docker compose exec -T redis id -u",
        "docker compose exec -T neo4j id -u",
        "docker inspect --format",
        "npx playwright install --with-deps chromium",
        "npm run test:e2e",
        "docker compose logs --no-color",
    )
    missing = [fragment for fragment in required_fragments if fragment not in normalized]
    assert missing == []

    for action in (
        "actions/checkout",
        "actions/setup-python",
        "actions/setup-node",
        "anchore/sbom-action",
        "anchore/scan-action",
    ):
        assert f"uses: {action}@" in WORKFLOW


def test_public_mirror_and_runner_runbook_covers_safety_boundary() -> None:
    assert RUNBOOK_PATH.is_file()
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
    lower = re.sub(r"\s+", " ", runbook.lower())
    required_phrases = (
        "private source repository",
        "history-free public ci mirror",
        "runtime, test, and build paths",
        "reviewed operations and runbook documentation",
        "isolated docker-in-docker",
        "/var/run/docker.sock",
        "host ports",
        "repository secrets",
        "github.actor == github.repository_owner",
        "github.triggering_actor == github.repository_owner",
        "owner-triggered events",
        "non-owner reruns are blocked",
        "dependabot",
        "bots",
        "collaborators",
        "outside actors",
        "fork pull requests never execute",
        "never approve untrusted fork jobs",
        "docs/superpowers/**",
        "docs/project-status.md",
        ".agent/",
        ".superpowers/",
        "files/",
        "research/",
        "archive",
        "master reference",
        "mirror-specific readme",
        "down --volumes --remove-orphans",
        "compose up --no-build --pull never --no-deps --abort-on-container-exit "
        "--exit-code-from configcheck configcheck",
        "docker compose --env-file .env.example pull --ignore-buildable redis neo4j",
        "fresh dind preload",
    )
    missing = [phrase for phrase in required_phrases if phrase not in lower]
    assert missing == []
    for label in ("self-hosted", "Linux", "X64", "recon-readiness"):
        assert label in runbook


def test_runbook_describes_the_workflow_lifetime_runner_model() -> None:
    runbook = re.sub(r"\s+", " ", RUNBOOK_PATH.read_text(encoding="utf-8").lower())
    required_phrases = (
        "workflow-lifetime runner process",
        "accepts jobs serially",
        "docker_host=tcp://127.0.0.1:2375",
        "at most one active run and one pending run",
        "never shares that dind with another runner",
        "destroyed after the whole workflow",
        "after the active workflow completes",
        "before serving another",
        "fixed integration ports",
        "unique compose projects",
        "unique image tags",
        "optional future hardening",
    )
    missing = [phrase for phrase in required_phrases if phrase not in runbook]
    assert missing == []
    assert "fresh runner workspace and fresh dind data volume for each job" not in runbook
    assert "allow it to accept one job" not in runbook
