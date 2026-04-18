from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.export import ensure_output_structure, write_outputs


def test_ensure_output_structure_creates_expected_directories(tmp_path: Path):
    ensure_output_structure(tmp_path)

    assert (tmp_path / "data" / "raw").exists()
    assert (tmp_path / "data" / "interim").exists()
    assert (tmp_path / "data" / "processed" / "events_flat").exists()
    assert (tmp_path / "data" / "processed" / "incidents").exists()
    assert (tmp_path / "reports").exists()
    assert (tmp_path / "notebooks").exists()


def test_write_outputs_writes_artifacts_and_respects_csv_flags(tmp_path: Path):
    events = pd.DataFrame(
        {
            "event_id": ["evt-1", "evt-2"],
            "event_date": ["2025-01-01", "2025-01-01"],
            "value": [1, 2],
        }
    )
    incidents = pd.DataFrame(
        {
            "incident_id": ["inc-1"],
            "incident_start_date": ["2025-01-01"],
            "event_count": [2],
        }
    )
    output_root = tmp_path / "processed"
    reports_root = tmp_path / "reports"

    write_outputs(
        events=events,
        incidents=incidents,
        schema_definition={"events_flat": {"event_id": {"dtype": "object"}}},
        data_quality_report={"event_row_count": 2},
        output_root=output_root,
        reports_root=reports_root,
        csv_sample_limit=1,
        write_csv_sample=True,
        write_full_csv=False,
    )

    assert (output_root / "events_flat.parquet").exists()
    assert (output_root / "incidents.parquet").exists()
    assert (output_root / "events_flat_sample.csv").exists()
    assert not (output_root / "events_flat.csv").exists()
    assert (output_root / "events_flat").exists()
    assert (output_root / "incidents").exists()
    assert json.loads((reports_root / "schema.json").read_text(encoding="utf-8"))["events_flat"]["event_id"]["dtype"] == "object"
    assert json.loads((reports_root / "data_quality_report.json").read_text(encoding="utf-8"))["event_row_count"] == 2
    feature_dictionary = (reports_root / "feature_dictionary.md").read_text(encoding="utf-8")
    assert "`incident_id`" in feature_dictionary
