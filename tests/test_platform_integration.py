from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app import worker
from app.adapters.ip import ShodanAdapter
from app.core.config import Settings
from app.core.queueing import InMemoryScanQueue
from app.core.rate_limit import InMemoryRateLimiter
from app.main import create_app
from app.storage.memory import InMemoryStore


def test_mocked_passive_provider_flows_api_queue_worker_store_and_graph(
    monkeypatch,
) -> None:
    config = Settings(
        AUTH_ENABLED=False,
        LOCAL_PRINCIPAL_SUB="integration-investigator",
        SHODAN_API_KEY="recorded-fixture-key",
        _env_file=None,
    )
    store = InMemoryStore()
    queue = InMemoryScanQueue()
    app = create_app(
        config,
        store=store,
        queue=queue,
        rate_limiter=InMemoryRateLimiter(100, 60),
    )

    async def recorded_provider_response(self, target):
        return json.loads(
            (Path(__file__).parent / "fixtures" / "shodan_host.json").read_text(
                encoding="utf-8"
            )
        )

    monkeypatch.setattr(ShodanAdapter, "run", recorded_provider_response)
    monkeypatch.setattr(ShodanAdapter, "get_rate_limit", lambda self: 0)

    with TestClient(app) as client:
        case = client.post("/v1/cases", json={"name": "Integration case"})
        assert case.status_code == 201
        created = client.post(
            f"/v1/cases/{case.json()['id']}/scans",
            json={
                "targets": [
                    {"target_type": "ip", "target_value": "203.0.113.10"}
                ],
                "adapter_ids": ["shodan"],
            },
        )
        assert created.status_code == 202
        scan = created.json()
        assert queue.jobs[scan["job_id"]] == scan["id"]

        result = client.portal.call(
            worker.run_case_scan_task,
            {"store": store, "settings": config},
            scan["id"],
            scan["owner_id"],
            scan["case_id"],
        )

        status = client.get(f"/v1/scans/{scan['id']}")
        graph = client.get(f"/v1/scans/{scan['id']}/graph")

    assert result["state"] == "succeeded"
    assert status.status_code == 200
    assert status.json()["state"] == "succeeded"
    assert status.json()["job_id"] == scan["job_id"]
    assert status.json()["adapter_runs"][0]["state"] == "succeeded"
    assert {node["entity_type"] for node in graph.json()["nodes"]} == {
        "ip",
        "domain",
    }
    provenance = graph.json()["provenance"][0]
    assert provenance["source_adapter_id"] == "shodan"
    assert provenance["adapter_version"] == "shodan-host-api-v1"
    assert provenance["source_target"] == {
        "target_type": "ip",
        "target_value": "203.0.113.10",
    }
