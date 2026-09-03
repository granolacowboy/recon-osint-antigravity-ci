# recon-osint-antigravity-ci

A **public, history-free CI/validation projection** of a scoped OSINT & attack-surface reconnaissance pipeline. This repository carries the runtime, tests, and build inputs used for automated validation of that pipeline — deliberately **without** the private source's commit history — so the architecture and quality gates can be reviewed publicly while sensitive development detail and secrets stay private.

> This is a reference/validation mirror, not a product. It does not accept public contributions and does not represent a production deployment or an authorization to scan any target.

## What it does

A modular recon pipeline that fans a target across independent, single-responsibility **adapters** and normalizes their output behind a common interface:

- **Identity & exposure:** `email`, `username`, `phone`, `social`, `breach` (credential exposure), `darkweb`
- **Infrastructure:** `domain`, `ip`, `network`, `cloud`, `metadata`, `web_archive`
- **Risk:** `vuln`, `threat_intel`, `corporate`, `geo`
- **Core:** an adapter `registry`, `auth`, and `config` (`app/core/`), containerized via the included `Dockerfile`.

Each adapter is isolated behind `app/adapters/base.py`, so sources can be added, disabled, or scoped per engagement without touching the core.

## Design principles

- **Scoped & authorized only** — recon runs against targets the operator is authorized to assess.
- **Deterministic, auditable output** — normalized records with provenance, suitable for CI assertions.
- **Security-first** — secrets via environment (`.env.example`), least privilege, no credentials in the tree (CI-scanned).
- **History-free public surface** — the public mirror is a projection; the private pipeline retains full history.

## Run

```bash
cp .env.example .env      # supply only the API keys for the adapters you enable
docker build -t recon-ci .
docker run --rm --env-file .env recon-ci   # runs the validation suite
```

## License

Apache-2.0. See [LICENSE](LICENSE).

---

<sub>Part of the MHSB Solutions applied-AI + security estate. Maintained by Rich Berman ([@granolacowboy](https://github.com/granolacowboy)) / [MHSB Solutions](https://github.com/MHSBai) · [granolacowboy.dev](https://granolacowboy.dev)</sub>
