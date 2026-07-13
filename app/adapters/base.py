import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.core.config import Settings, settings
from app.core.logging import logger
from app.schemas.base import TargetEntity
from app.schemas.outcomes import (
    AdapterError,
    AdapterMetadata,
    AdapterNoResultsError,
    AdapterOutcome,
    AdapterState,
    AdapterUnavailableError,
    RetryableAdapterError,
)


class ToolAdapter(ABC):
    """
    Abstract Base Class for RECON OSINT tool adapters.
    """

    metadata: AdapterMetadata | None = None

    def __init__(self, config: Settings | None = None) -> None:
        self.config = config or settings

    @abstractmethod
    def validate(self, target: TargetEntity) -> bool:
        """
        Validate whether this adapter can process the given target entity.
        """
        pass

    @abstractmethod
    async def run(self, target: TargetEntity) -> Any:
        """
        Execute the tool against the target. Returns raw tool output.
        """
        pass

    @abstractmethod
    def parse(self, raw_output: Any) -> List[TargetEntity]:
        """
        Parse raw tool output into a list of newly discovered TargetEntities.
        """
        pass

    def get_proxies(self) -> Optional[Dict[str, str]]:
        """
        Return a proxy dictionary if the adapter requires routing traffic through proxies.
        """
        return None

    def get_timeout(self) -> int:
        """
        Return the execution timeout in seconds for this adapter.
        """
        return 30

    def get_rate_limit(self) -> float:
        """
        Return the rate limit delay in seconds for this adapter.
        """
        return 0.5

    def get_retry_delay(self, attempt: int) -> float:
        """Return an exponential delay after a retryable failed attempt."""
        return float(min(2 ** (attempt - 1), 10))

    def get_metadata(self) -> AdapterMetadata:
        """Resolve typed metadata from the explicit registry."""
        if self.metadata is not None:
            return self.metadata

        from app.adapters.registry import get_registration_for_adapter

        registration = get_registration_for_adapter(type(self))
        return registration.metadata_for(self.config)

    @staticmethod
    def _outcome(
        metadata: AdapterMetadata,
        state: AdapterState,
        *,
        findings: tuple[TargetEntity, ...] = (),
        attempts: int = 0,
        code: str = "",
    ) -> AdapterOutcome:
        outcome = AdapterOutcome(
            adapter_id=metadata.adapter_id,
            state=state,
            findings=findings,
            attempts=attempts,
            code=code,
        )
        logger.bind(
            adapter_id=metadata.adapter_id,
            outcome_code=outcome.code,
            attempts=attempts,
        ).info("adapter_outcome")
        return outcome

    async def execute(self, target: TargetEntity) -> AdapterOutcome:
        """
        Validate, execute, and parse while preserving truthful terminal state.
        """
        metadata = self.get_metadata()
        if not metadata.enabled:
            return self._outcome(
                metadata,
                AdapterState.UNAVAILABLE,
                code=metadata.unavailable_reason or "adapter_disabled",
            )

        try:
            valid = self.validate(target)
        except Exception:
            return self._outcome(
                metadata, AdapterState.FAILED, code="validation_failed"
            )
        if not valid:
            return self._outcome(
                metadata, AdapterState.FAILED, code="invalid_target"
            )

        for attempt in range(1, metadata.max_attempts + 1):
            try:
                rate_limit = self.get_rate_limit()
                if rate_limit > 0:
                    await asyncio.sleep(rate_limit)
                raw_output = await asyncio.wait_for(
                    self.run(target), timeout=self.get_timeout()
                )
                parsed = self.parse(raw_output)
                findings = tuple(parsed)
                if not all(isinstance(item, TargetEntity) for item in findings):
                    raise TypeError("adapter parse returned a non-entity finding")
                if findings:
                    return self._outcome(
                        metadata,
                        AdapterState.SUCCEEDED,
                        findings=findings,
                        attempts=attempt,
                    )
                return self._outcome(
                    metadata, AdapterState.NO_RESULTS, attempts=attempt
                )
            except asyncio.CancelledError:
                raise
            except (RetryableAdapterError, asyncio.TimeoutError):
                if attempt >= metadata.max_attempts:
                    return self._outcome(
                        metadata,
                        AdapterState.RETRYABLE_FAILURE,
                        attempts=attempt,
                    )
                retry_delay = self.get_retry_delay(attempt)
                if retry_delay > 0:
                    await asyncio.sleep(retry_delay)
            except AdapterNoResultsError as exc:
                return self._outcome(
                    metadata,
                    AdapterState.NO_RESULTS,
                    attempts=attempt,
                    code=exc.code,
                )
            except AdapterUnavailableError as exc:
                return self._outcome(
                    metadata,
                    AdapterState.UNAVAILABLE,
                    attempts=attempt,
                    code=exc.code,
                )
            except AdapterError as exc:
                return self._outcome(
                    metadata,
                    AdapterState.FAILED,
                    attempts=attempt,
                    code=exc.code,
                )
            except Exception:
                return self._outcome(
                    metadata, AdapterState.FAILED, attempts=attempt
                )

        raise AssertionError("adapter retry loop terminated without an outcome")
