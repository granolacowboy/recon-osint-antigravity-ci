from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path

import pytest

from scripts.render_openvex import render_openvex
from scripts.verify_grype_vex import verify_grype_vex_report


ROOT = Path(__file__).resolve().parents[1]
SOURCE_VEX = ROOT / "security" / "recon-api.openvex.json"
RUN_PRODUCT = "recon-osint-api:ci-29288139142-2"
PYTHON_PURL = "pkg:generic/python@3.13.14"
CVE = "CVE-2026-15308"


def _source_document() -> dict[str, object]:
    return json.loads(SOURCE_VEX.read_text(encoding="utf-8"))


def _write_document(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _valid_grype_report() -> dict[str, object]:
    return {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2099-0001"},
                "artifact": {"purl": "pkg:generic/example@1.0"},
            }
        ],
        "ignoredMatches": [
            {
                "vulnerability": {"id": CVE},
                "artifact": {"purl": PYTHON_PURL},
                "appliedIgnoreRules": [
                    {"namespace": "vex", "vex-status": "not_affected"}
                ],
            }
        ],
        "source": {
            "type": "image",
            "target": {
                "userInput": RUN_PRODUCT,
                "tags": [RUN_PRODUCT],
            },
        },
    }


def test_renderer_binds_only_the_reviewed_ci_product(tmp_path: Path) -> None:
    source_bytes = SOURCE_VEX.read_bytes()
    destination = tmp_path / "run.openvex.json"
    issued_at = datetime(2026, 7, 13, 22, 30, 45, tzinfo=UTC)

    render_openvex(
        SOURCE_VEX,
        destination,
        RUN_PRODUCT,
        issued_at=issued_at,
    )

    assert SOURCE_VEX.read_bytes() == source_bytes
    source = _source_document()
    rendered = json.loads(destination.read_text(encoding="utf-8"))
    assert rendered["@id"] == f"{source['@id']}/ci-29288139142-2"
    assert rendered["timestamp"] == "2026-07-13T22:30:45Z"
    assert rendered["version"] == 1

    statement = rendered["statements"][0]
    assert statement["timestamp"] == "2026-07-13T22:30:45Z"
    assert statement["vulnerability"] == {"name": CVE}
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert statement["products"] == [
        {
            "@id": RUN_PRODUCT,
            "subcomponents": [{"@id": PYTHON_PURL}],
        },
        {
            "@id": "recon-osint-api:local",
            "subcomponents": [{"@id": PYTHON_PURL}],
        },
    ]

    expected = deepcopy(source)
    expected["@id"] = rendered["@id"]
    expected["timestamp"] = rendered["timestamp"]
    expected["statements"][0]["timestamp"] = statement["timestamp"]
    expected["statements"][0]["products"][0]["@id"] = RUN_PRODUCT
    assert rendered == expected


@pytest.mark.parametrize(
    "product",
    (
        "",
        "recon-osint-api:ci",
        "recon-osint-api:ci-latest",
        "recon-osint-api:ci-12-3-extra",
        "other:ci-12-3",
        "recon-osint-api:ci-12-3;echo-pwned",
    ),
)
def test_renderer_rejects_non_run_scoped_products(
    tmp_path: Path, product: str
) -> None:
    with pytest.raises(ValueError, match="run-scoped"):
        render_openvex(SOURCE_VEX, tmp_path / "out.json", product)


def test_renderer_rejects_overwriting_the_reviewed_source() -> None:
    with pytest.raises(ValueError, match="destination"):
        render_openvex(SOURCE_VEX, SOURCE_VEX, RUN_PRODUCT)


def test_renderer_rejects_unreviewed_statement_shapes(tmp_path: Path) -> None:
    source = _source_document()
    malformed: list[dict[str, object]] = []

    wrong_status = deepcopy(source)
    wrong_status["statements"][0]["status"] = "fixed"
    malformed.append(wrong_status)

    wrong_justification = deepcopy(source)
    wrong_justification["statements"][0]["justification"] = (
        "inline_mitigations_already_exist"
    )
    malformed.append(wrong_justification)

    wrong_component = deepcopy(source)
    wrong_component["statements"][0]["products"][0]["subcomponents"] = [
        {"@id": "pkg:generic/python@3.15.0"}
    ]
    malformed.append(wrong_component)

    duplicate_product = deepcopy(source)
    duplicate_product["statements"][0]["products"].append(
        deepcopy(duplicate_product["statements"][0]["products"][0])
    )
    malformed.append(duplicate_product)

    missing_cve = deepcopy(source)
    missing_cve["statements"][0]["vulnerability"]["name"] = "CVE-2099-9999"
    malformed.append(missing_cve)

    for index, document in enumerate(malformed):
        path = tmp_path / f"malformed-{index}.json"
        _write_document(path, document)
        with pytest.raises(ValueError, match="reviewed"):
            render_openvex(path, tmp_path / f"out-{index}.json", RUN_PRODUCT)


def test_grype_report_proves_the_exact_image_vex_was_applied(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "grype.json"
    _write_document(report_path, _valid_grype_report())

    summary = verify_grype_vex_report(report_path, RUN_PRODUCT)

    assert summary == {
        "active_matches": 1,
        "ignored_matches": 1,
        "vex_status": "not_affected",
    }


@pytest.mark.parametrize(
    "mutation, message",
    (
        ("active", "remains active"),
        ("missing_ignored", "exactly one ignored"),
        ("wrong_rule", "VEX not_affected"),
        ("wrong_product", "run-scoped image"),
        ("sbom", "Docker image"),
    ),
)
def test_grype_report_rejects_missing_or_broad_vex_evidence(
    tmp_path: Path, mutation: str, message: str
) -> None:
    report = _valid_grype_report()
    if mutation == "active":
        report["matches"].append(
            {
                "vulnerability": {"id": CVE},
                "artifact": {"purl": PYTHON_PURL},
            }
        )
    elif mutation == "missing_ignored":
        report["ignoredMatches"] = []
    elif mutation == "wrong_rule":
        report["ignoredMatches"][0]["appliedIgnoreRules"] = [
            {"namespace": "config", "vex-status": "not_affected"}
        ]
    elif mutation == "wrong_product":
        report["source"]["target"]["userInput"] = "recon-osint-api:ci-1-1"
    elif mutation == "sbom":
        report["source"]["type"] = "file"

    report_path = tmp_path / f"{mutation}.json"
    _write_document(report_path, report)
    with pytest.raises(ValueError, match=message):
        verify_grype_vex_report(report_path, RUN_PRODUCT)
