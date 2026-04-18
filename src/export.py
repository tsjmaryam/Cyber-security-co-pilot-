from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def ensure_output_structure(project_root: Path) -> None:
    for directory in [
        project_root / "data" / "raw",
        project_root / "data" / "interim",
        project_root / "data" / "processed" / "events_flat",
        project_root / "data" / "processed" / "incidents",
        project_root / "reports",
        project_root / "notebooks",
    ]:
        directory.mkdir(parents=True, exist_ok=True)


def write_outputs(
    events: pd.DataFrame,
    incidents: pd.DataFrame,
    schema_definition: dict[str, Any],
    data_quality_report: dict[str, Any],
    output_root: Path,
    reports_root: Path,
    csv_sample_limit: int,
    write_csv_sample: bool,
    write_full_csv: bool,
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)
    events_output = output_root / "events_flat"
    incidents_output = output_root / "incidents"
    events_output.mkdir(parents=True, exist_ok=True)
    incidents_output.mkdir(parents=True, exist_ok=True)
    events.to_parquet(output_root / "events_flat.parquet", index=False)
    incidents.to_parquet(output_root / "incidents.parquet", index=False)
    events.to_parquet(events_output, index=False, partition_cols=["event_date"])
    incidents.to_parquet(incidents_output, index=False, partition_cols=["incident_start_date"])
    if write_full_csv:
        events.to_csv(output_root / "events_flat.csv", index=False)
    if write_csv_sample:
        events.head(csv_sample_limit).to_csv(output_root / "events_flat_sample.csv", index=False)
    (reports_root / "schema.json").write_text(json.dumps(schema_definition, indent=2), encoding="utf-8")
    (reports_root / "data_quality_report.json").write_text(json.dumps(data_quality_report, indent=2), encoding="utf-8")
    (reports_root / "feature_dictionary.md").write_text(_build_feature_dictionary(), encoding="utf-8")


def _build_feature_dictionary() -> str:
    entries = [
        ("global_sort_key", "Canonical deterministic event ordering key."),
        ("actor_key", "Primary actor identifier fallback chain for analysis."),
        ("session_key", "Session-like identifier using access key, actor/IP/day, or IP/user agent/day."),
        ("actor_event_rank", "Order of an event within its actor_key."),
        ("session_event_rank", "Order of an event within its session_key."),
        ("ip_event_rank", "Order of an event within its source IP."),
        ("seconds_since_prev_session_event", "Time gap from the previous event in the same session_key."),
        ("same_event_source_as_prev_session_event", "Whether the prior session event had the same event_source."),
        ("same_event_name_as_prev_session_event", "Whether the prior session event had the same event_name."),
        ("is_root_user", "Identity convenience flag for root activity."),
        ("is_assumed_role", "Identity convenience flag for assumed-role activity."),
        ("is_iam_user", "Identity convenience flag for IAM user activity."),
        ("is_aws_service_call", "Identity convenience flag for AWS service-originated activity."),
        ("is_console_login", "Rule-based flag for console login activity."),
        ("is_auth_related", "Rule-based flag for authentication or credential operations."),
        ("is_s3_related", "Rule-based flag for S3 events."),
        ("is_iam_related", "Rule-based flag for IAM events."),
        ("is_ec2_related", "Rule-based flag for EC2 events."),
        ("is_recon_like_api", "Rule-based flag for reconnaissance-like APIs."),
        ("is_privilege_change_api", "Rule-based flag for privilege-modifying APIs."),
        ("is_resource_creation_api", "Rule-based flag for create or launch APIs."),
        ("actor_events_prev_5m", "Count of prior events by actor in the preceding five minutes."),
        ("actor_events_prev_1h", "Count of prior events by actor in the preceding hour."),
        ("ip_events_prev_5m", "Count of prior events by source IP in the preceding five minutes."),
        ("ip_events_prev_1h", "Count of prior events by source IP in the preceding hour."),
        ("same_event_name_prev_5m", "Count of prior events with the same event_name in the preceding five minutes."),
        ("same_event_name_prev_1h", "Count of prior events with the same event_name in the preceding hour."),
        ("same_event_source_prev_5m", "Count of prior events with the same event_source in the preceding five minutes."),
        ("same_event_source_prev_1h", "Count of prior events with the same event_source in the preceding hour."),
        ("incident_id", "Deterministic identifier for an inactivity-bounded actor/IP activity cluster."),
        ("ordered_event_name_sequence", "Ordered pipe-delimited event sequence for each incident."),
        ("ordered_event_source_sequence", "Ordered pipe-delimited event source sequence for each incident."),
        ("raw_event_row_indices", "JSON array pointer back to row indices in events_flat."),
    ]
    lines = ["# Feature Dictionary", ""]
    for name, description in entries:
        lines.append(f"- `{name}`: {description}")
    return "\n".join(lines) + "\n"
