from __future__ import annotations

import json
import logging
import sys
from io import StringIO

from app.core.config import Settings
from app.core.logging import configure_logging, logger


def test_logging_defaults_to_structured_stdout_without_file_sink() -> None:
    output = StringIO()
    config = Settings(LOG_FILE=None, _env_file=None)
    try:
        configure_logging(config, stdout=output)
        logger.bind(
            request_id="request-1", outcome_code="succeeded", target_count=1
        ).info("scan_outcome")

        payload = json.loads(output.getvalue())
        assert payload["record"]["message"] == "scan_outcome"
        assert payload["record"]["extra"] == {
            "request_id": "request-1",
            "outcome_code": "succeeded",
            "target_count": 1,
        }
    finally:
        configure_logging(config, stdout=sys.stdout)


def test_logging_adds_file_sink_only_when_explicitly_configured(tmp_path) -> None:
    output = StringIO()
    log_file = tmp_path / "recon.jsonl"
    config = Settings(LOG_FILE=str(log_file), _env_file=None)
    try:
        configure_logging(config, stdout=output)
        logger.bind(outcome_code="ready").info("service_outcome")

        assert log_file.exists()
        payload = json.loads(log_file.read_text(encoding="utf-8"))
        assert payload["record"]["message"] == "service_outcome"
    finally:
        configure_logging(Settings(LOG_FILE=None, _env_file=None), stdout=sys.stdout)


def test_http_client_info_logs_cannot_emit_credential_bearing_urls() -> None:
    output = StringIO()
    config = Settings(LOG_FILE=None, _env_file=None)
    try:
        configure_logging(config, stdout=output)
        logging.getLogger("httpx").info(
            "GET https://api.shodan.io/host/private-target?key=private-credential"
        )
        logging.getLogger("neo4j").warning(
            "query parameters contained private-target"
        )

        assert "private-target" not in output.getvalue()
        assert "private-credential" not in output.getvalue()
        assert output.getvalue() == ""
    finally:
        configure_logging(config, stdout=sys.stdout)


def test_sink_recursively_redacts_messages_extras_and_exception_details() -> None:
    output = StringIO()
    config = Settings(LOG_FILE=None, _env_file=None)
    try:
        configure_logging(config, stdout=output)
        logger.bind(credential="nested-private").error(
            "GET https://provider.test/path?access_token=private-value&X-Amz-Signature=signed-private "
            "api_key=also-private token=assignment-private",
        )
        logging.getLogger("provider").error(
            "provider exception",
            exc_info=(ValueError, ValueError("password=exception-private"), None),
        )

        rendered = output.getvalue()
        assert "private-value" not in rendered
        assert "also-private" not in rendered
        assert "signed-private" not in rendered
        assert "assignment-private" not in rendered
        assert "nested-private" not in rendered
        assert "exception-private" not in rendered
        payloads = [json.loads(line) for line in rendered.splitlines()]
        assert payloads[0]["record"]["extra"]["credential"] == "[REDACTED]"
        assert payloads[1]["record"]["extra"]["exception_type"] == "ValueError"
    finally:
        configure_logging(config, stdout=sys.stdout)
