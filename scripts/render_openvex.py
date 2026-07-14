"""Render the reviewed backend OpenVEX statement for one CI image."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import tempfile


CVE = "CVE-2026-15308"
PYTHON_PURL = "pkg:generic/python@3.13.14"
SOURCE_CI_PRODUCT = "recon-osint-api:ci"
LOCAL_PRODUCT = "recon-osint-api:local"
STATUS = "not_affected"
JUSTIFICATION = "vulnerable_code_not_in_execute_path"
RUN_PRODUCT_PATTERN = re.compile(
    r"recon-osint-api:ci-(?P<run>[0-9]+)-(?P<attempt>[0-9]+)"
)


def _reviewed_document_id(document: object) -> str:
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("source is not the reviewed OpenVEX document")

    document_id = document.get("@id")
    statements = document.get("statements")
    if (
        not isinstance(document_id, str)
        or not document_id
        or not isinstance(statements, list)
        or len(statements) != 1
        or not isinstance(statements[0], dict)
    ):
        raise ValueError("source is not the reviewed OpenVEX document")

    statement = statements[0]
    expected_products = [
        {
            "@id": SOURCE_CI_PRODUCT,
            "subcomponents": [{"@id": PYTHON_PURL}],
        },
        {
            "@id": LOCAL_PRODUCT,
            "subcomponents": [{"@id": PYTHON_PURL}],
        },
    ]
    if (
        statement.get("vulnerability") != {"name": CVE}
        or statement.get("status") != STATUS
        or statement.get("justification") != JUSTIFICATION
        or statement.get("products") != expected_products
        or not isinstance(statement.get("impact_statement"), str)
        or not statement["impact_statement"].strip()
    ):
        raise ValueError("source is not the reviewed OpenVEX statement")
    return document_id


def _issued_timestamp(issued_at: datetime | None) -> str:
    instant = issued_at if issued_at is not None else datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("issued_at must be timezone-aware")
    return (
        instant.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _write_atomically(destination: Path, document: dict[str, object]) -> None:
    if not destination.parent.is_dir():
        raise ValueError("destination parent directory must already exist")

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(document, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def render_openvex(
    source_path: str | Path,
    destination_path: str | Path,
    product_id: str,
    *,
    issued_at: datetime | None = None,
) -> None:
    """Render a run-scoped copy of the reviewed OpenVEX statement."""
    product_match = RUN_PRODUCT_PATTERN.fullmatch(product_id)
    if product_match is None:
        raise ValueError("product must be a run-scoped CI image tag")

    source = Path(source_path).resolve()
    destination = Path(destination_path).resolve()
    if os.path.normcase(str(source)) == os.path.normcase(str(destination)):
        raise ValueError("destination must not overwrite the reviewed source")

    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("source is not the reviewed OpenVEX document") from exc

    source_document_id = _reviewed_document_id(document)
    rendered = deepcopy(document)
    rendered_statement = rendered["statements"][0]
    timestamp = _issued_timestamp(issued_at)
    suffix = (
        f"ci-{product_match.group('run')}-{product_match.group('attempt')}"
    )

    rendered["@id"] = f"{source_document_id.rstrip('/')}/{suffix}"
    rendered["version"] = 1
    rendered["timestamp"] = timestamp
    rendered_statement["timestamp"] = timestamp
    rendered_statement["products"][0]["@id"] = product_id

    _write_atomically(destination, rendered)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind the reviewed backend OpenVEX statement to one CI image."
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--product", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    render_openvex(arguments.source, arguments.destination, arguments.product)
    print("rendered run-scoped backend OpenVEX document")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
