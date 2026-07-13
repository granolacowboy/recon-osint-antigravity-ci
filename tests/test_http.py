from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from app.schemas.outcomes import AdapterError, RetryableAdapterError
from app.utils import http


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeClient:
    def __init__(self, results: Iterable[Any]) -> None:
        self.results = iter(results)
        self.calls = 0

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, *args: Any, **kwargs: Any) -> FakeResponse:
        self.calls += 1
        result = next(self.results)
        if isinstance(result, BaseException):
            raise result
        return result


def _install_client(
    monkeypatch: pytest.MonkeyPatch, client: FakeClient
) -> None:
    monkeypatch.setattr(
        http.httpx,
        "AsyncClient",
        lambda **kwargs: client,
    )


@pytest.mark.asyncio
async def test_fetch_json_retries_transient_status_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient(
        [FakeResponse(503), FakeResponse(200, {"status": "ok"})]
    )
    sleep = AsyncMock()
    _install_client(monkeypatch, client)
    monkeypatch.setattr(http.asyncio, "sleep", sleep)

    result = await http.fetch_json("https://example.invalid/api", retries=2)

    assert result == {"status": "ok"}
    assert client.calls == 2
    assert sleep.await_count == 1


@pytest.mark.asyncio
async def test_fetch_json_permanent_4xx_fails_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient([FakeResponse(401)])
    sleep = AsyncMock()
    _install_client(monkeypatch, client)
    monkeypatch.setattr(http.asyncio, "sleep", sleep)

    with pytest.raises(AdapterError, match="status 401"):
        await http.fetch_json("https://example.invalid/api", retries=3)

    assert client.calls == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_fetch_json_exhausted_transport_failure_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = httpx.Request("GET", "https://example.invalid/api")
    client = FakeClient(
        [
            httpx.ConnectError("offline", request=request),
            httpx.ConnectError("offline", request=request),
            httpx.ConnectError("offline", request=request),
        ]
    )
    sleep = AsyncMock()
    _install_client(monkeypatch, client)
    monkeypatch.setattr(http.asyncio, "sleep", sleep)

    with pytest.raises(RetryableAdapterError):
        await http.fetch_json("https://example.invalid/api", retries=3)

    assert client.calls == 3
    assert sleep.await_count == 2


@pytest.mark.asyncio
async def test_fetch_json_does_not_sleep_after_final_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient([FakeResponse(429), FakeResponse(429)])
    sleep = AsyncMock()
    _install_client(monkeypatch, client)
    monkeypatch.setattr(http.asyncio, "sleep", sleep)

    with pytest.raises(RetryableAdapterError):
        await http.fetch_json("https://example.invalid/api", retries=2)

    assert client.calls == 2
    assert sleep.await_count == 1


@pytest.mark.asyncio
async def test_fetch_json_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient([asyncio.CancelledError()])
    _install_client(monkeypatch, client)

    with pytest.raises(asyncio.CancelledError):
        await http.fetch_json("https://example.invalid/api")
