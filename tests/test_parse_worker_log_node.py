"""Boundary coverage for parallel worker log parsing."""

from ascp_agent.graph import parse_worker_log_node


def test_parse_worker_log_node_preserves_unicode_metadata_for_empty_log():
    """An empty worker artifact must not discard identifying Unicode metadata."""
    result = parse_worker_log_node(
        {
            "worker_id": "作業者-Δ",
            "table": "需要_表",
            "log_content": "",
        }
    )

    assert result["log_templates"] == []
    assert result["intermediate_query_results"] == [
        {"worker_id": "作業者-Δ", "table": "需要_表", "errors": []}
    ]
    assert result["audit_trail"] == [
        {"event": "PARALLEL_WORKER_PARSED", "worker_id": "作業者-Δ", "table": "需要_表"}
    ]
