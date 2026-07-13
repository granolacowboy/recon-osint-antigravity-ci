"""Verify that Grype applied the reviewed backend VEX statement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


CVE = "CVE-2026-15308"
PYTHON_PURL = "pkg:generic/python@3.13.14"
RUN_PRODUCT_PATTERN = re.compile(r"recon-osint-api:ci-[0-9]+-[0-9]+")


def _matches_vulnerability(match: object, vulnerability_id: str) -> bool:
    return (
        isinstance(match, dict)
        and isinstance(match.get("vulnerability"), dict)
        and match["vulnerability"].get("id") == vulnerability_id
    )


def verify_grype_vex_report(
    report_path: str | Path,
    expected_product: str,
) -> dict[str, int | str]:
    """Return a summary after verifying run-scoped VEX evidence."""
    if RUN_PRODUCT_PATTERN.fullmatch(expected_product) is None:
        raise ValueError("expected product must be a run-scoped image")

    try:
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("report must be valid Grype JSON") from exc
    if not isinstance(report, dict):
        raise ValueError("report must be a Grype JSON object")

    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("report source must be a Docker image")
    target = source.get("target")
    if (
        not isinstance(target, dict)
        or target.get("userInput") != expected_product
        or not isinstance(target.get("tags"), list)
        or expected_product not in target["tags"]
    ):
        raise ValueError("report does not describe the exact run-scoped image")

    active_matches = report.get("matches")
    ignored_matches = report.get("ignoredMatches")
    if not isinstance(active_matches, list) or not isinstance(
        ignored_matches, list
    ):
        raise ValueError("report must contain Grype match lists")

    if any(_matches_vulnerability(match, CVE) for match in active_matches):
        raise ValueError(f"{CVE} remains active in the backend image")

    ignored_for_cve = [
        match
        for match in ignored_matches
        if _matches_vulnerability(match, CVE)
    ]
    if (
        len(ignored_for_cve) != 1
        or not isinstance(ignored_for_cve[0].get("artifact"), dict)
        or ignored_for_cve[0]["artifact"].get("purl") != PYTHON_PURL
    ):
        raise ValueError(
            f"expected exactly one ignored {CVE} match for reviewed Python"
        )

    applied_rules = ignored_for_cve[0].get("appliedIgnoreRules")
    if not isinstance(applied_rules, list) or not any(
        isinstance(rule, dict)
        and rule.get("namespace") == "vex"
        and rule.get("vex-status") == "not_affected"
        for rule in applied_rules
    ):
        raise ValueError("ignored match lacks the VEX not_affected rule")

    return {
        "active_matches": len(active_matches),
        "ignored_matches": len(ignored_matches),
        "vex_status": "not_affected",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Grype applied the backend run-scoped VEX statement."
    )
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--product", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    summary = verify_grype_vex_report(arguments.report, arguments.product)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
