from __future__ import annotations

import json
from pathlib import Path

from src.demo_stream import build_demo_scenarios, iter_demo_batches, write_demo_stream
from src.ingest import ingest_records
from src.normalize import normalize_records


def test_demo_stream_builds_purpose_doc_scenarios():
    scenarios = build_demo_scenarios()
    assert len(scenarios) == 3
    assert {scenario.scenario_id for scenario in scenarios} == {
        "unusual_login_incomplete_network",
        "complete_root_privilege_case",
        "device_context_unavailable",
    }
    assert any(scenario.expected_blind_spot for scenario in scenarios)
    assert any(scenario.expected_blind_spot is None for scenario in scenarios)


def test_demo_stream_batches_can_be_ingested(tmp_path: Path):
    manifest = write_demo_stream(tmp_path, batch_size=1)
    assert (tmp_path / "demo_manifest.json").exists()
    assert manifest["scenario_count"] if "scenario_count" in manifest else len(manifest["scenarios"]) == 3

    raw_records, metrics = ingest_records(tmp_path)
    assert metrics.total_records_parsed > 0
    normalized = normalize_records(raw_records)
    assert normalized.empty is False
    assert set(normalized["event_name"].unique()) >= {"ConsoleLogin", "CreateAccessKey", "RunInstances"}
    assert "source_ip_address" in normalized.columns


def test_demo_stream_manifest_describes_expected_operator_behavior(tmp_path: Path):
    write_demo_stream(tmp_path, batch_size=2)
    manifest = json.loads((tmp_path / "demo_manifest.json").read_text(encoding="utf-8"))
    scenarios = {item["scenario_id"]: item for item in manifest["scenarios"]}
    assert scenarios["unusual_login_incomplete_network"]["expected_operator_move"].startswith("double_check")
    assert scenarios["complete_root_privilege_case"]["expected_blind_spot"] is None
    assert "device" in scenarios["device_context_unavailable"]["coverage_categories"]
