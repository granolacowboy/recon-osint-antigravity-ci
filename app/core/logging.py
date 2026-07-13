from __future__ import annotations

import logging
import sys
from typing import TextIO

from loguru import logger

from app.core.config import Settings, settings
from app.redaction import redact_text, redact_value


def _sanitize_record(record: dict) -> None:
    record["message"] = redact_text(str(record.get("message", "")))
    record["extra"] = redact_value(record.get("extra", {}))


class InterceptHandler(logging.Handler):
    """Route standard-library records through the structured Loguru sink."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = logging.currentframe(), 2
        while frame is not None and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        bound = logger
        if record.exc_info and record.exc_info[0] is not None:
            bound = bound.bind(exception_type=record.exc_info[0].__name__)
        bound.opt(depth=depth).log(level, record.getMessage())


def configure_logging(
    config: Settings, *, stdout: TextIO = sys.stdout
) -> None:
    """Use serialized stdout; add a file only when explicitly configured."""
    logging.basicConfig(
        handlers=[InterceptHandler()], level=config.LOG_LEVEL, force=True
    )
    # Client request logs can contain raw targets and credential-bearing query URLs.
    for noisy_client in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy_client).setLevel(logging.ERROR)
    logging.getLogger("neo4j").setLevel(logging.ERROR)
    logger.remove()
    logger.configure(patcher=_sanitize_record)
    logger.add(stdout, serialize=True, level=config.LOG_LEVEL)
    if config.LOG_FILE:
        try:
            logger.add(
                config.LOG_FILE,
                serialize=True,
                level=config.LOG_LEVEL,
                rotation="10 MB",
                encoding="utf-8",
            )
        except (OSError, ValueError):
            logger.bind(log_file_configured=True).warning("log_file_sink_unavailable")


def setup_logging() -> None:
    """Compatibility entry point for callers that use global settings."""
    configure_logging(settings)


setup_logging()


ARQ_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "loggers": {
        "arq": {"handlers": [], "level": settings.LOG_LEVEL, "propagate": True}
    },
}

__all__ = ["ARQ_LOG_CONFIG", "configure_logging", "logger", "setup_logging"]
