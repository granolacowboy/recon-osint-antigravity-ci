# Self-hosted CI

## Purpose and trust boundary

The private source repository remains the system of record. An account-level
Actions stop can prevent job creation even when the target is self-hosted. In
that situation, use the history-free public CI mirror described below; do not
make the private source repository public.

The public workflow triggers only for pushes to `main` and branches matching
`codex/**`. Pull requests do not trigger this public self-hosted workflow;
same-repository owner branch pushes attach the named checks to the pull request
head SHA. Fork code cannot schedule this repository-scoped runner. Fork pull
requests never execute on it. The external controller, not mutable workflow
YAML, is the trust boundary.

As defense in depth, every job has this single-line guard:

```text
github.event_name == 'push' && github.actor == github.repository_owner && github.triggering_actor == github.repository_owner
```

Non-owner reruns are blocked even when the original event was permitted.
Dependabot, other bots, collaborators, and outside actors are also excluded.
Operators must never approve untrusted fork jobs or weaken the admission
policy; reproduce a reviewed change on an owner-controlled, same-repository
branch instead.

The workflow grants only `contents: read`. It does not reference repository
secrets, upload or download artifacts, or persist dependency and vulnerability
database caches. Every third-party action is pinned to a full commit SHA. The
backend, frontend, integration, and container gates all select exactly:

```yaml
runs-on: [self-hosted, Linux, X64, recon-readiness]
```

Register each runner at repository scope with all four labels: `self-hosted`,
`Linux`, `X64`, and `recon-readiness`. Do not add a broader organization runner
group to this workflow.

## External controller admission

Before registering any runner, an external trusted controller must inspect the
queued run and fail closed unless all of these values match:

- the event is `push`;
- the repository is `granolacowboy/recon-osint-antigravity-ci`;
- the owner and triggering actor are both `granolacowboy`;
- the workflow is `.github/workflows/ci.yml`;
- the ref is `refs/heads/main` or matches `refs/heads/codex/**`; and
- the head commit is the exact reviewed head SHA.

No repository runner remains online while no approved job is being admitted.
The controller obtains short-lived registration material only after admission,
never bakes it into an image, and never exposes it to workflow steps. It starts
each runner container with the matching environment values described below.

## One-job isolated Docker-in-Docker runner

The controller provisions one `config.sh --ephemeral --disableupdate` runner
per job. Every admission receives a fresh runner container and workspace, a
fresh privileged DinD daemon, a private network namespace, a unique runner
name, no mounts, no host ports, and no host Docker socket. Privilege is confined
to the disposable DinD daemon; the workflow runner is not privileged. The
runner and DinD share only that pair's private network namespace, where
`DOCKER_HOST=tcp://127.0.0.1:2375` reaches the daemon over loopback.

The runner must never have `/var/run/docker.sock` mounted or available as a
socket. The DinD API and all Compose service ports remain inside the private
namespace. The jobs receive no repository secrets. The runner image must
provide the Docker CLI with Compose, Git, curl, and the system dependencies
required by the pinned Python, Node.js, and Playwright setup actions.

Each ephemeral runner is automatically deregistered by GitHub after exactly one
job. The controller verifies deregistration, then destroys only that runner,
DinD daemon, network, and workspace before provisioning another in the same
controller slot. Multiple jobs may execute concurrently only when each has its
own isolated runner/DinD pair and lifecycle. The fixed integration ports
`16379` and `17687` are safe because namespaces are separate, not because a
runner accepts jobs serially.

The controller supplies `RECON_EPHEMERAL_RUNNER=1`, sets the nonempty
`RECON_RUNNER_INSTANCE` to the configured `RUNNER_NAME`, and sets
`DOCKER_HOST=tcp://127.0.0.1:2375`. Before checkout, every job's first step
fails closed unless `RECON_EPHEMERAL_RUNNER=1`, `RECON_RUNNER_INSTANCE` is
nonempty and equals `RUNNER_NAME`, `DOCKER_HOST=tcp://127.0.0.1:2375`, and
`/var/run/docker.sock` is not a socket. This in-workflow observation cannot
prove `--ephemeral`; controller registration and GitHub's one-job deregistration
supply that guarantee.

The workflow retains global workflow concurrency with the static
`recon-readiness-self-hosted` group and `cancel-in-progress: false`. This limits
the repository to one active workflow run and one pending run across allowed
branches, but it does not create or clean runner state. Clean state comes from
per-job ephemerality, not post-workflow timing.

## Job lifecycle and cleanup

For each approved job, a controller slot performs this lifecycle:

1. Verify the queued run metadata and exact reviewed head SHA before obtaining
   registration material.
2. Create the dedicated runner container and workspace, privileged DinD daemon,
   private network namespace, and unique runner name with no mounts or host
   ports.
3. Configure the repository-scoped runner with
   `config.sh --ephemeral --disableupdate`, the exact four labels above, and the
   matching boundary environment values.
4. Allow the runner to accept exactly one job. Let the workflow use per-run,
   per-attempt, per-job `COMPOSE_PROJECT_NAME` values and per-run, per-attempt
   `IMAGE_TAG` values.
5. Let each Docker job execute its `if: always()` teardown. Integration runs
   `docker compose down --volumes --remove-orphans`. Container acceptance does
   the same, then attempts both run-tagged image removals while preserving the
   Compose failure status.
6. Whether the job succeeds, fails, times out, or is cancelled, wait for
   GitHub's automatic one-job deregistration, verify it, and destroy that
   runner, DinD daemon, namespace, and workspace before the slot admits another
   job.

Never reuse dirty job state and never attach a second runner to a DinD daemon.
Workflow cleanup limits state during a job; controller destruction is the
cancellation backstop when an `if: always()` step cannot complete. Concurrent
controller slots must never destroy or reuse another slot's resources.

Container acceptance deliberately invokes
`bash ./scripts/start.sh --detach --no-build` after both unique images have
passed SBOM generation and vulnerability scanning. A fresh DinD preload then
runs
`docker compose --env-file .env.example pull --ignore-buildable redis neo4j`.
The explicit environment file makes placeholder-backed Compose interpolation
independent of any repository `.env`. The explicit service list and
`--ignore-buildable` leave the scanned application images untouched; the
Compose model pins both datastore images to full SHA-256 digests. This is the
only permitted network preload and makes the later pull-denied startup work on
an empty DinD image cache.

The no-build path runs the configuration preflight with
`docker compose up --no-build --pull never --no-deps --abort-on-container-exit --exit-code-from configcheck configcheck`.
It then starts the full stack with `docker compose up --no-build --pull never`.
Neither command can implicitly build or substitute a registry image, so
acceptance can use only the scanned local tags and fails if either is missing.

## Run-scoped backend VEX evidence

The checked-in backend OpenVEX document is the reviewed source statement, not
the file passed directly to Grype. Before scanning, CI validates that statement
and renders a temporary copy whose application product is the exact run image,
`recon-osint-api:ci-<run-id>-<run-attempt>`. The generated document has a unique
document ID, current UTC document and statement timestamps, and `version: 1`.
It changes only the reviewed CI product binding; the local product, impact
statement, status, justification, and provenance remain intact.

Python remains the subcomponent `pkg:generic/python@3.13.14`. It must never be
promoted to the VEX product because that would make a broader claim about every
installation of that Python release. Likewise, do not create a shared mutable
image alias merely to make VEX matching succeed. The exact run tag preserves
the application-level statement and the workflow's per-run image isolation.

The backend vulnerability gate continues to scan the Docker image, not a
detached SBOM. It emits a runner-local JSON report, and a separate proof step
requires CVE-2026-15308 to appear exactly once in `ignoredMatches` for the
reviewed Python subcomponent with an applied VEX `not_affected` rule. The scan
still fails on any fixable critical or high vulnerability that remains active.
The generated VEX and JSON report live only under the runner temporary
directory; this bootstrap workflow does not upload them, and supervisor
destruction removes them with the disposable runner workspace.

## History-free public CI mirror fallback

The public fallback is a disposable, allowlisted source snapshot, not a clone
of the private source repository. Build it in a new empty directory outside the
private checkout. Copy only runtime, test, and build paths plus reviewed
operations and runbook documentation. Inspect that exact file list, initialize
a new Git repository, and create a new root commit. Never use
`git push --mirror`, copy the private `.git` directory, or push a private branch
to the public remote. The root README may be replaced by a mirror-specific
README that describes the projection and links back to the private project
without copying private status or research material.

The public mirror allowlist excludes `research/`, `archive/`, `archives/`,
`files/`, `.agent/`, `.superpowers/`, `docs/superpowers/**`, and
`docs/project-status.md`. It also excludes session exports, investigation
evidence, every master reference file, local `.env` files, logs, caches,
generated results, and packaged archives such as `*.zip`, `*.tar`, and
`*.tar.gz`. The project-status hygiene maintained in the private repository
does not make that status file part of the mirror. Public mirror creation must
fail closed if an unlisted path is present. Scan the resulting snapshot for
credentials, local filesystem paths, personal data, and target data before any
push. A force-push is not a substitute for this pre-publication review because
previously exposed objects may remain retrievable.

Push only the sanitized root commit to a dedicated public repository. Have the
external controller admit that exact reviewed commit and provision one isolated
repository-scoped ephemeral runner/DinD pair per job with the same four labels.
Record the commit and run URL, and verify every runner's deregistration and
destruction. The public mirror must contain no repository secrets and must not
have credentials that can read the private source repository. Treat the public
result as validation of that snapshot only; merge decisions and release history
remain in the private repository.
