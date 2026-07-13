# Self-hosted CI

## Purpose and trust boundary

The private source repository remains the system of record. Its `CI` workflow
runs for pull requests and pushes to `main` when GitHub will schedule the jobs.
An account-level Actions stop can prevent job creation even when the target is
self-hosted. In that situation, use the history-free public CI mirror described
below; do not make the private source repository public.

The workflow grants only `contents: read`. It does not reference repository
secrets, upload or download artifacts, or persist dependency and vulnerability
database caches. Every third-party action is pinned to a full commit SHA. The
backend, frontend, integration, and container gates all select exactly:

```yaml
runs-on: [self-hosted, Linux, X64, recon-readiness]
```

Register the runner at repository scope with all four labels: `self-hosted`,
`Linux`, `X64`, and `recon-readiness`. Do not add a broader organization runner
group to this workflow.

Every job requires both `github.actor == github.repository_owner` and
`github.triggering_actor == github.repository_owner`, and also has a
same-repository pull-request guard. Only owner-originated, owner-triggered
events can reach the runner. Non-owner reruns are blocked even when the
original event was permitted. Fork pull requests never execute on the runner,
even in the public fallback repository. Dependabot, other bots, collaborators,
and outside actors are also excluded. Operators must never approve untrusted
fork jobs or weaken any guard; reproduce a reviewed change on an
owner-controlled, same-repository branch instead.

## Isolated Docker-in-Docker runner

The current implementation uses one repository-scoped workflow-lifetime runner
process. It accepts jobs serially and shares the dedicated DinD container
network namespace with one isolated Docker-in-Docker daemon. The runner uses
`DOCKER_HOST=tcp://127.0.0.1:2375`; that loopback endpoint exists only inside
the shared container network namespace. This runner never shares that DinD
with another runner, so two workflow jobs cannot use the daemon concurrently.

The runner must never bind-mount the host Docker socket at
`/var/run/docker.sock`. The DinD API and all Compose service ports remain
inside the dedicated namespace; publish no host ports. Privilege, if the DinD
daemon requires it, is confined to that disposable daemon rather than granting
the workflow access to the host.

Supply only short-lived runner registration material to the bootstrap
supervisor; do not bake it into an image or expose it to workflow steps. The
jobs receive no repository secrets. The runner image must provide the Docker
CLI with Compose, Git, curl, and the system dependencies required by the pinned
Python, Node.js, and Playwright setup actions.

The fixed integration ports `16379` and `17687` are safe only because the one
runner process accepts jobs serially. Redis, Neo4j, API, and browser acceptance
ports bind inside the shared DinD namespace and never on the physical host.
Unique Compose projects isolate Docker resources by run, attempt, and job;
unique image tags isolate the backend and frontend images by run and attempt.
The workflow cleanup removes each Compose project, its volumes and orphans, and
the two run-tagged application images before the next applicable job or run.

The workflow uses one repository-global static concurrency group with
`cancel-in-progress: false`. GitHub therefore permits at most one active run
and one pending run for this workflow across every branch and pull request; a
newer queued run may replace an older pending run, but it does not cancel or
interleave with the active run. Repository-global serialization is required
because separate refs target the same dedicated runner and DinD lifecycle.

## Job lifecycle and cleanup

1. Create a dedicated private container network namespace, DinD daemon, and
   workflow workspace with no host socket mount or host port mappings.
2. Start one repository-scoped runner process in that namespace, configure
   `DOCKER_HOST=tcp://127.0.0.1:2375`, and apply the exact labels above.
3. Keep that runner process for the complete workflow and let it accept the
   matching jobs serially.
4. Let the workflow use per-run, per-attempt, per-job
   `COMPOSE_PROJECT_NAME` values and per-run, per-attempt `IMAGE_TAG` values.
5. Let each Docker job execute its `if: always()` teardown. Integration runs
   `docker compose down --volumes --remove-orphans`. Container acceptance does
   the same, then attempts both run-tagged image removals while preserving the
   Compose failure status.
6. After the complete workflow succeeds, fails, times out, or is cancelled,
   have the bootstrap supervisor unregister and destroy the runner, DinD
   daemon, private namespace, and workspace. The runner, DinD, and workspace
   are destroyed after the whole workflow, not after an individual job.
7. After the active workflow completes, the operator or bootstrap supervisor
   must finish that destruction and verify cleanup before serving another
   pending workflow run.
8. Before the host starts another workflow runner, verify that no runner
   process, DinD daemon, Compose project, network, volume, image, or workspace
   from the prior workflow remains.

Do not reuse dirty workflow state and never attach a second runner to the same
DinD. The workflow cleanup limits cross-run state; supervisor destruction is
the cancellation backstop when an `if: always()` step cannot complete.

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

An ephemeral runner with a fresh DinD daemon and workspace for every job is
optional future hardening. It is not the current implementation and must not be
claimed by operational checks until the bootstrap supervisor actually provides
that lifecycle.

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

Push only the sanitized root commit to a dedicated public repository. Attach a
repository-scoped ephemeral runner with the same four labels, run the same
workflow, record the commit and run URL, and then remove the runner. The public
mirror must contain no repository secrets and must not have credentials that
can read the private source repository. Treat the public result as validation
of that snapshot only; merge decisions and release history remain in the
private repository.
