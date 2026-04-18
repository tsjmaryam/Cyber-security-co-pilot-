from __future__ import annotations

from typing import Any

import pandas as pd

from .ingest import IngestMetrics


DERIVATION_NOTES = {
    "global_sort_key": "Deterministic ordering key from event_time_epoch_ms, source_file_name, record_index_in_file, and event_id.",
    "actor_key": "First non-null of user_arn, principal_id, access_key_id, source_ip_address, else UNKNOWN_ACTOR.",
    "session_key": "Session-like grouping key based on access key, actor/IP/day, or IP/user-agent/day fallback.",
    "actor_event_rank": "1-based order of events within actor_key under canonical event ordering.",
    "session_event_rank": "1-based order of events within session_key under canonical event ordering.",
    "ip_event_rank": "1-based order of events within source_ip_address under canonical event ordering.",
    "seconds_since_prev_session_event": "Elapsed seconds from the previous event within session_key.",
    "same_event_source_as_prev_session_event": "Whether event_source matches the previous event in the same session_key.",
    "same_event_name_as_prev_session_event": "Whether event_name matches the previous event in the same session_key.",
    "event_date": "UTC calendar date derived from event_time.",
    "event_hour_utc": "UTC hour derived from event_time.",
    "event_day_of_week_utc": "UTC day name derived from event_time.",
    "event_month_utc": "UTC month number derived from event_time.",
    "is_weekend_utc": "True when event_time falls on Saturday or Sunday in UTC.",
    "is_root_user": "True when user_type is Root or the ARN ends with :root.",
    "is_assumed_role": "True when identity indicates an assumed role.",
    "is_iam_user": "True when identity indicates an IAM user.",
    "is_aws_service_call": "True when invoked_by is set or user_type implies an AWS service principal.",
    "is_console_login": "Rule-driven flag from event_flag_rules.yaml.",
    "is_auth_related": "Rule-driven flag from event_flag_rules.yaml.",
    "is_s3_related": "Rule-driven flag from event_flag_rules.yaml.",
    "is_iam_related": "Rule-driven flag from event_flag_rules.yaml.",
    "is_ec2_related": "Rule-driven flag from event_flag_rules.yaml.",
    "is_recon_like_api": "Rule-driven flag from event_flag_rules.yaml.",
    "is_privilege_change_api": "Rule-driven flag from event_flag_rules.yaml.",
    "is_resource_creation_api": "Rule-driven flag from event_flag_rules.yaml.",
    "actor_events_prev_5m": "Count of prior events for the same actor_key in the previous five minutes.",
    "actor_events_prev_1h": "Count of prior events for the same actor_key in the previous hour.",
    "ip_events_prev_5m": "Count of prior events for the same source_ip_address in the previous five minutes.",
    "ip_events_prev_1h": "Count of prior events for the same source_ip_address in the previous hour.",
    "same_event_name_prev_5m": "Count of prior events with the same event_name in the previous five minutes.",
    "same_event_name_prev_1h": "Count of prior events with the same event_name in the previous hour.",
    "same_event_source_prev_5m": "Count of prior events with the same event_source in the previous five minutes.",
    "same_event_source_prev_1h": "Count of prior events with the same event_source in the previous hour.",
    "incident_start_date": "UTC date derived from incident_start_time for partitioned export.",
}


def build_data_quality_report(events: pd.DataFrame, incidents: pd.DataFrame, metrics: IngestMetrics) -> dict[str, Any]:
    null_rates = {column: round(float(events[column].isna().mean()), 6) for column in events.columns}
    top_values = {}
    for column in ["actor_key", "source_ip_address", "event_name", "event_source", "aws_region"]:
        if column in events:
            top_values[column] = events[column].dropna().astype(str).value_counts().head(10).to_dict()
    return {
        "total_files_read": metrics.total_files_read,
        "total_records_parsed": metrics.total_records_parsed,
        "total_malformed_files": metrics.total_malformed_files,
        "total_malformed_records": metrics.total_malformed_records,
        "malformed_file_examples": metrics.malformed_file_examples,
        "malformed_record_reasons": metrics.malformed_record_reasons,
        "duplicate_event_ids": int(events["event_id"].dropna().duplicated().sum()) if "event_id" in events else 0,
        "invalid_timestamps": int(events["event_time"].isna().sum()) if "event_time" in events else 0,
        "rows_missing_event_name_and_event_source": int((events["event_name"].isna() & events["event_source"].isna()).sum()),
        "impossible_incident_durations": int((incidents["incident_duration_seconds"] < 0).sum()) if not incidents.empty else 0,
        "event_row_count": int(len(events)),
        "incident_row_count": int(len(incidents)),
        "null_rates": null_rates,
        "time_range_coverage": {
            "event_time_min": events["event_time"].min().isoformat() if not events.empty and events["event_time"].notna().any() else None,
            "event_time_max": events["event_time"].max().isoformat() if not events.empty and events["event_time"].notna().any() else None,
        },
        "top_values": top_values,
    }


def validate_outputs(events: pd.DataFrame, incidents: pd.DataFrame, metrics: IngestMetrics) -> list[str]:
    errors: list[str] = []
    if metrics.total_records_parsed <= 0:
        errors.append("Parsed record count must be greater than zero.")
    if len(events) != metrics.total_records_parsed:
        errors.append("Event table row count does not equal successfully parsed records.")
    if not incidents.empty and len(incidents) > len(events):
        errors.append("Incident table row count must be less than or equal to event table row count.")
    if "global_sort_key" in events and not events["global_sort_key"].is_monotonic_increasing:
        errors.append("Event table is not canonically sorted by global_sort_key.")
    if not incidents.empty and incidents["event_count"].lt(1).any():
        errors.append("Every incident must reference a non-empty ordered subset of events.")
    return errors


def build_schema_definition(events: pd.DataFrame, incidents: pd.DataFrame) -> dict[str, Any]:
    return {"events_flat": _schema_for_frame(events), "incidents": _schema_for_frame(incidents)}


def _schema_for_frame(frame: pd.DataFrame) -> dict[str, Any]:
    columns: dict[str, Any] = {}
    for column in frame.columns:
        columns[column] = {
            "dtype": str(frame[column].dtype),
            "nullable": bool(frame[column].isna().any()),
            "derivation_logic": DERIVATION_NOTES.get(column, "Source field or passthrough normalization."),
        }
    return columns
