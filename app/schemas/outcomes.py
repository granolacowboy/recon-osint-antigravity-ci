from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Sequence, overload

from app.schemas.base import TargetEntity


class AdapterState(str, Enum):
    """Truthful terminal states for one adapter invocation."""

    QUEUED = "queued"
    RUNNING = "running"
    UNAVAILABLE = "unavailable"
    SUCCEEDED = "succeeded"
    NO_RESULTS = "no_results"
    RETRYABLE_FAILURE = "retryable_failure"
    FAILED = "failed"


@dataclass(frozen=True)
class AdapterMetadata:
    """Static and resolved policy metadata for an adapter."""

    adapter_id: str
    display_name: str
    target_types: tuple[str, ...]
    passive: bool
    enabled: bool = False
    unavailable_reason: str | None = None
    max_attempts: int = 3

    def __post_init__(self) -> None:
        if not self.adapter_id:
            raise ValueError("adapter_id must not be empty")
        if not self.target_types:
            raise ValueError("target_types must not be empty")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")


@dataclass(frozen=True)
class AdapterOutcome(Sequence[TargetEntity]):
    """Typed result that cannot confuse failures with valid empty results."""

    adapter_id: str
    state: AdapterState
    findings: tuple[TargetEntity, ...] = field(default_factory=tuple)
    attempts: int = 0
    code: str = ""

    def __post_init__(self) -> None:
        if self.state is AdapterState.SUCCEEDED and not self.findings:
            raise ValueError("succeeded outcomes must contain findings")
        if self.state is not AdapterState.SUCCEEDED and self.findings:
            raise ValueError("only succeeded outcomes may contain findings")
        if self.attempts < 0:
            raise ValueError("attempts must not be negative")
        if not self.code:
            object.__setattr__(self, "code", self.state.value)

    @property
    def successful(self) -> bool:
        return self.state in {AdapterState.SUCCEEDED, AdapterState.NO_RESULTS}

    def __len__(self) -> int:
        return len(self.findings)

    @overload
    def __getitem__(self, index: int) -> TargetEntity: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[TargetEntity, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> TargetEntity | tuple[TargetEntity, ...]:
        return self.findings[index]

    def __iter__(self) -> Iterator[TargetEntity]:
        return iter(self.findings)


class AdapterError(RuntimeError):
    """Base exception for an adapter failure with known semantics."""

    def __init__(self, message: str, *, code: str = "adapter_failure") -> None:
        super().__init__(message)
        self.code = code


class RetryableAdapterError(AdapterError):
    """A transient adapter failure that may succeed on a later attempt."""


class AdapterNoResultsError(AdapterError):
    """A provider truthfully reported that the target has no result."""


class AdapterUnavailableError(AdapterError):
    """Provider configuration or authorization makes the adapter unavailable."""


class HTTPStatusAdapterError(AdapterError):
    def __init__(self, status_code: int) -> None:
        super().__init__(
            f"HTTP request failed with status {status_code}",
            code=f"http_status_{status_code}",
        )
        self.status_code = status_code


class ScanState(str, Enum):
    """Truthful aggregate states for a queued scan task."""

    UNAVAILABLE = "unavailable"
    SUCCEEDED = "succeeded"
    NO_RESULTS = "no_results"
    RETRYABLE_FAILURE = "retryable_failure"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanOutcome:
    """Structured worker result that deliberately excludes the raw target."""

    scan_id: str
    target_type: str
    state: ScanState
    adapter_outcomes: tuple[AdapterOutcome, ...] = field(default_factory=tuple)
    discovered_count: int = 0
    code: str = ""

    def __post_init__(self) -> None:
        if self.discovered_count < 0:
            raise ValueError("discovered_count must not be negative")
        if not self.code:
            object.__setattr__(self, "code", self.state.value)

    @property
    def successful(self) -> bool:
        return self.state in {ScanState.SUCCEEDED, ScanState.NO_RESULTS}
