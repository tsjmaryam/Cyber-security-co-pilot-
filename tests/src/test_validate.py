from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from src.ingest import IngestMetrics
from src.validate import build_data_quality_report, build_schema_definition, validate_outputs


def _metrics(total_records: int = 2) -> IngestMetrics:
    return IngestMetrics(
        total_files_read=1,
        total_records_parsed=total_records,
        total_malformed_files=0,
        total_malformed_records=0,
        malformed_file_examples=[],
        malformed_record_reasons={},
    )


def test_validate_outputs_reports_multiple_edge_case_failures():
    events = pd.DataFrame(
        {
            "global_sort_key": [2, 1],
            "event_id": ["evt-1", "evt-1"],
            "event_time": [datetime.now(timezone.utc), pd.NaT],
            "event_name": [None, None],
            "event_source": [None, None],
        }
    )
    incidents = pd.DataFrame({"event_count": [0, 1], "incident_duration_seconds": [-5, 10]})

    errors = validate_outputs(events, incidents, _metrics(total_records=1))

    assert "Event table row count does not equal successfully parsed records." in errors
    assert "Event table is not canonically sorted by global_sort_key." in errors
    assert "Every incident must reference a non-empty ordered subset of events." in errors


def test_build_data_quality_report_and_schema_definition_include_expected_fields():
    events = pd.DataFrame(
        {
            "global_sort_key": [1, 2],
            "event_id": ["evt-1", "evt-1"],
            "event_time": [datetime(2025, 1, 1, tzinfo=timezone.utc), pd.NaT],
            "event_name": ["ConsoleLogin", None],
            "event_source": ["signin.amazonaws.com", None],
            "actor_key": ["actor-1", "actor-1"],
            "source_ip_address": ["203.0.113.10", "203.0.113.10"],
            "aws_region": ["us-east-1", "us-east-1"],
        }
    )
    incidents = pd.DataFrame({"incident_duration_seconds": [-1], "incident_start_date": [pd.Timestamp("2025-01-01")]})

    report = build_data_quality_report(events, incidents, _metrics(total_records=2))
    schema = build_schema_definition(events, incidents)

    assert report["duplicate_event_ids"] == 1
    assert report["invalid_timestamps"] == 1
    assert report["rows_missing_event_name_and_event_source"] == 1
    assert report["impossible_incident_durations"] == 1
    assert "actor_key" in report["top_values"]
    assert schema["events_flat"]["global_sort_key"]["derivation_logic"].startswith("Deterministic ordering key")
