import asyncio
from typing import Any

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.schemas.outcomes import (
    AdapterError,
    HTTPStatusAdapterError,
    RetryableAdapterError,
)


_TRANSIENT_STATUS_CODES = frozenset({408, 425, 429})


async def fetch_json(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: int = 30,
    retries: int = 3,
) -> Any:
    """
    Fetch JSON with bounded retries and observable failure semantics.

    URLs and query parameters are intentionally excluded from logs because
    they may contain targets or credentials.
    """
    if retries < 1:
        raise ValueError("retries must be at least one")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    backoff = settings.HTTP_BACKOFF_SECONDS
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(1, retries + 1):
            try:
                response = await client.get(url, params=params, headers=headers)
            except asyncio.CancelledError:
                raise
            except httpx.RequestError as exc:
                if attempt >= retries:
                    raise RetryableAdapterError(
                        "HTTP transport failed after all attempts"
                    ) from exc
                logger.bind(
                    attempt=attempt,
                    outcome_code="transport_retry",
                    error_type=type(exc).__name__,
                ).warning("http_request_retry")
                if backoff > 0:
                    await asyncio.sleep(backoff)
                backoff *= 2
                continue

            status_code = response.status_code
            if 200 <= status_code < 300:
                try:
                    return response.json()
                except (TypeError, ValueError) as exc:
                    raise AdapterError("HTTP response was not valid JSON") from exc

            transient = (
                status_code in _TRANSIENT_STATUS_CODES or status_code >= 500
            )
            if transient:
                if attempt >= retries:
                    raise RetryableAdapterError(
                        f"HTTP request failed after all attempts with status {status_code}"
                    )
                logger.bind(
                    attempt=attempt,
                    status_code=status_code,
                    outcome_code="status_retry",
                ).warning("http_request_retry")
                if backoff > 0:
                    await asyncio.sleep(backoff)
                backoff *= 2
                continue

            raise HTTPStatusAdapterError(status_code)

    raise AssertionError("HTTP retry loop terminated without a result")
