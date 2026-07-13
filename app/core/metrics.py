from __future__ import annotations

from collections import defaultdict
from threading import Lock


class ProcessMetrics:
    """Process-local counters; deployment aggregation is intentionally external."""

    def __init__(self) -> None:
        self._http: dict[tuple[str, str, int], int] = defaultdict(int)
        self._created_scans = 0
        self._cancelled_scans = 0
        self._adapter_outcomes: dict[tuple[str, str], int] = defaultdict(int)
        self._adapter_latency_sum: dict[str, float] = defaultdict(float)
        self._adapter_latency_count: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def record_http(self, method: str, path: str, status: int) -> None:
        with self._lock:
            self._http[(method, path, status)] += 1

    def record_created_scan(self) -> None:
        with self._lock:
            self._created_scans += 1

    def record_cancelled_scan(self) -> None:
        with self._lock:
            self._cancelled_scans += 1

    def record_adapter(self, adapter_id: str, outcome: str, latency: float) -> None:
        with self._lock:
            self._adapter_outcomes[(adapter_id, outcome)] += 1
            self._adapter_latency_sum[adapter_id] += latency
            self._adapter_latency_count[adapter_id] += 1

    @staticmethod
    def _label(value: object) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    def render(
        self,
        *,
        queue_depth: int | None = None,
        shared_adapter_metrics: dict[str, dict[str, float]] | None = None,
    ) -> str:
        with self._lock:
            adapter_outcomes = defaultdict(int, self._adapter_outcomes)
            adapter_latency_sum = defaultdict(float, self._adapter_latency_sum)
            adapter_latency_count = defaultdict(int, self._adapter_latency_count)
            shared = shared_adapter_metrics or {}
            for key, count in shared.get("outcomes", {}).items():
                adapter_id, separator, outcome = key.partition("|")
                if separator and adapter_id and outcome:
                    adapter_outcomes[(adapter_id, outcome)] += int(count)
            for adapter_id, value in shared.get("latency_sum", {}).items():
                adapter_latency_sum[adapter_id] += float(value)
            for adapter_id, value in shared.get("latency_count", {}).items():
                adapter_latency_count[adapter_id] += int(value)
            lines = [
                "# HELP recon_http_requests_total Process-local HTTP requests.",
                "# TYPE recon_http_requests_total counter",
            ]
            for (method, path, status), count in sorted(self._http.items()):
                lines.append(
                    'recon_http_requests_total{method="%s",path="%s",status="%s"} %d'
                    % (
                        self._label(method),
                        self._label(path),
                        status,
                        count,
                    )
                )
            lines.extend(
                [
                    "# HELP recon_scans_created_total Process-local created scans.",
                    "# TYPE recon_scans_created_total counter",
                    f"recon_scans_created_total {self._created_scans}",
                    "# HELP recon_scans_cancelled_total Process-local cancelled scans.",
                    "# TYPE recon_scans_cancelled_total counter",
                    f"recon_scans_cancelled_total {self._cancelled_scans}",
                    "# HELP recon_queue_depth Jobs waiting in the configured scan queue.",
                    "# TYPE recon_queue_depth gauge",
                    f"recon_queue_depth {queue_depth if queue_depth is not None else 'NaN'}",
                    "# HELP recon_adapter_outcomes_total Process-local adapter outcomes.",
                    "# TYPE recon_adapter_outcomes_total counter",
                ]
            )
            for (adapter_id, outcome), count in sorted(
                adapter_outcomes.items()
            ):
                lines.append(
                    'recon_adapter_outcomes_total{adapter_id="%s",outcome="%s"} %d'
                    % (self._label(adapter_id), self._label(outcome), count)
                )
            lines.extend(
                [
                    "# HELP recon_adapter_latency_seconds Process-local adapter latency.",
                    "# TYPE recon_adapter_latency_seconds summary",
                ]
            )
            for adapter_id in sorted(adapter_latency_count):
                label = self._label(adapter_id)
                lines.append(
                    f'recon_adapter_latency_seconds_sum{{adapter_id="{label}"}} '
                    f"{adapter_latency_sum[adapter_id]:.9f}"
                )
                lines.append(
                    f'recon_adapter_latency_seconds_count{{adapter_id="{label}"}} '
                    f"{adapter_latency_count[adapter_id]}"
                )
            return "\n".join(lines) + "\n"
