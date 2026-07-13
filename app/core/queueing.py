from __future__ import annotations

from abc import ABC, abstractmethod


ADAPTER_OUTCOME_METRICS_KEY = "recon:metrics:adapter:outcomes"
ADAPTER_LATENCY_SUM_METRICS_KEY = "recon:metrics:adapter:latency_sum"
ADAPTER_LATENCY_COUNT_METRICS_KEY = "recon:metrics:adapter:latency_count"


class QueueError(RuntimeError):
    """Transient scan queue operation failed."""


class ScanQueue(ABC):
    @abstractmethod
    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str: ...

    @abstractmethod
    async def abort(self, job_id: str) -> bool: ...

    @abstractmethod
    async def health(self) -> bool: ...

    @abstractmethod
    async def depth(self) -> int: ...

    @abstractmethod
    async def shared_adapter_metrics(self) -> dict[str, dict[str, float]]: ...

    @abstractmethod
    async def close(self) -> None: ...


class InMemoryScanQueue(ScanQueue):
    """Deterministic process-local queue for tests and explicit local use."""

    def __init__(self) -> None:
        self.jobs: dict[str, str] = {}
        self.aborted_job_ids: list[str] = []
        self._healthy = True

    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str:
        if not self._healthy:
            raise QueueError("queue is unavailable")
        if job_id in self.jobs and self.jobs[job_id] != scan_id:
            raise QueueError("queue job id is already in use")
        self.jobs[job_id] = scan_id
        return job_id

    async def abort(self, job_id: str) -> bool:
        if not self._healthy:
            raise QueueError("queue is unavailable")
        if job_id not in self.aborted_job_ids:
            self.aborted_job_ids.append(job_id)
        return True

    async def health(self) -> bool:
        return self._healthy

    async def depth(self) -> int:
        if not self._healthy:
            raise QueueError("queue is unavailable")
        return sum(
            job_id not in self.aborted_job_ids for job_id in self.jobs
        )

    async def shared_adapter_metrics(self) -> dict[str, dict[str, float]]:
        return {"outcomes": {}, "latency_sum": {}, "latency_count": {}}

    async def close(self) -> None:
        self._healthy = False


class ArqScanQueue(ScanQueue):
    """ARQ/Redis queue adapter; Redis remains transient infrastructure."""

    def __init__(
        self,
        redis_pool: object,
        *,
        owns_pool: bool = True,
        queue_name: str | None = None,
        health_check_key: str | None = None,
    ) -> None:
        from arq.constants import default_queue_name, health_check_key_suffix

        self._redis = redis_pool
        self._owns_pool = owns_pool
        self._queue_name = queue_name or default_queue_name
        self._health_check_key = health_check_key or (
            self._queue_name + health_check_key_suffix
        )

    async def enqueue(
        self, scan_id: str, owner_id: str, case_id: str, job_id: str
    ) -> str:
        try:
            job = await self._redis.enqueue_job(
                "run_case_scan_task",
                scan_id,
                owner_id,
                case_id,
                _job_id=job_id,
                _queue_name=self._queue_name,
            )
        except Exception as exc:
            raise QueueError("queue enqueue failed") from exc
        if job is None:
            try:
                from arq.constants import job_key_prefix, result_key_prefix

                job_key = job_key_prefix + job_id
                result_key = result_key_prefix + job_id
                job_exists = bool(await self._redis.exists(job_key))
                result_exists = bool(await self._redis.exists(result_key))
                if not job_exists and result_exists:
                    await self._redis.delete(result_key)
                    job = await self._redis.enqueue_job(
                        "run_case_scan_task",
                        scan_id,
                        owner_id,
                        case_id,
                        _job_id=job_id,
                        _queue_name=self._queue_name,
                    )
            except Exception as exc:
                raise QueueError("queue could not verify an existing job") from exc
            if job is None and not job_exists:
                raise QueueError("queue did not return a job id")
            if job is None:
                return job_id
        if not getattr(job, "job_id", None):
            raise QueueError("queue did not return a job id")
        queued_job_id = str(job.job_id)
        if queued_job_id != job_id:
            raise QueueError("queue returned an unexpected job id")
        return queued_job_id

    async def abort(self, job_id: str) -> bool:
        try:
            from arq.jobs import Job

            return bool(
                await Job(job_id, self._redis, self._queue_name).abort(timeout=5)
            )
        except Exception as exc:
            raise QueueError("queue abort failed") from exc

    async def health(self) -> bool:
        try:
            if not await self._redis.ping():
                return False
            return bool(await self._redis.exists(self._health_check_key))
        except Exception:
            return False

    async def depth(self) -> int:
        try:
            return int(await self._redis.zcard(self._queue_name))
        except Exception as exc:
            raise QueueError("queue depth lookup failed") from exc

    async def shared_adapter_metrics(self) -> dict[str, dict[str, float]]:
        try:
            raw_outcomes, raw_sums, raw_counts = (
                await self._redis.hgetall(ADAPTER_OUTCOME_METRICS_KEY),
                await self._redis.hgetall(ADAPTER_LATENCY_SUM_METRICS_KEY),
                await self._redis.hgetall(ADAPTER_LATENCY_COUNT_METRICS_KEY),
            )

            def decode(mapping: dict) -> dict[str, float]:
                return {
                    (key.decode() if isinstance(key, bytes) else str(key)): float(value)
                    for key, value in mapping.items()
                }

            return {
                "outcomes": decode(raw_outcomes),
                "latency_sum": decode(raw_sums),
                "latency_count": decode(raw_counts),
            }
        except Exception as exc:
            raise QueueError("shared adapter metrics lookup failed") from exc

    async def close(self) -> None:
        if not self._owns_pool:
            return
        close = getattr(self._redis, "aclose", None)
        if close is not None:
            await close()
            return
        close = getattr(self._redis, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result
        wait_closed = getattr(self._redis, "wait_closed", None)
        if wait_closed is not None:
            await wait_closed()
