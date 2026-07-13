from app.core.metrics import ProcessMetrics


def test_process_metrics_merges_bounded_shared_worker_adapter_metrics() -> None:
    metrics = ProcessMetrics()
    rendered = metrics.render(
        queue_depth=2,
        shared_adapter_metrics={
            "outcomes": {"shodan|succeeded": 3},
            "latency_sum": {"shodan": 1.25},
            "latency_count": {"shodan": 3},
        },
    )

    assert 'adapter_id="shodan",outcome="succeeded"} 3' in rendered
    assert 'adapter_id="shodan"} 1.250000000' in rendered
    assert 'adapter_id="shodan"} 3' in rendered
    assert "recon_queue_depth 2" in rendered
