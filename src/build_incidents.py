from __future__ import annotations

import json
from typing import Any

import pandas as pd


def build_incidents(events: pd.DataFrame, incident_gap_minutes: int, ordered_sequence_limit: int) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame()
    frame = events.sort_values(
        ["event_time", "actor_key", "source_ip_address", "global_sort_key"],
        kind="mergesort",
        na_position="last",
    ).reset_index(drop=True)
    partition_key = frame["actor_key"].fillna("UNKNOWN_ACTOR") + "|" + frame["source_ip_address"].fillna("NO_IP")
    previous_partition = partition_key.shift(1)
    previous_time = frame["event_time"].shift(1)
    gap_seconds = (frame["event_time"] - previous_time).dt.total_seconds()
    new_incident = (
        partition_key.ne(previous_partition)
        | previous_time.isna()
        | gap_seconds.isna()
        | gap_seconds.gt(incident_gap_minutes * 60)
    )
    frame["incident_group_id"] = new_incident.cumsum().astype("Int64")

    grouped = frame.groupby("incident_group_id", sort=False, dropna=False)
    incidents = grouped.agg(
        actor_key=("actor_key", "first"),
        incident_start_time=("event_time", "min"),
        incident_end_time=("event_time", "max"),
        event_count=("event_id", "size"),
        distinct_event_names=("event_name", "nunique"),
        distinct_event_sources=("event_source", "nunique"),
        distinct_regions=("aws_region", "nunique"),
        error_event_count=("is_error", lambda series: int(series.fillna(False).sum())),
        success_event_count=("success", lambda series: int(series.fillna(False).sum())),
        first_event_name=("event_name", _first_non_null),
        last_event_name=("event_name", _last_non_null),
        top_event_name=("event_name", _top_mode),
        contains_console_login=("is_console_login", lambda series: bool(series.fillna(False).any())),
        contains_recon_like_api=("is_recon_like_api", lambda series: bool(series.fillna(False).any())),
        contains_privilege_change_api=("is_privilege_change_api", lambda series: bool(series.fillna(False).any())),
        contains_resource_creation_api=("is_resource_creation_api", lambda series: bool(series.fillna(False).any())),
        primary_source_ip_address=("source_ip_address", _mode_or_na),
    ).reset_index()

    sequence_frame = grouped.agg(
        resource_types_seen=("resource_types_concat", _merge_pipe_values),
        user_agents_seen=("user_agent", lambda series: _join_unique(series, ordered_sequence_limit)),
        ordered_event_name_sequence=("event_name", lambda series: _truncate_pipe_sequence(series, ordered_sequence_limit)),
        ordered_event_source_sequence=("event_source", lambda series: _truncate_pipe_sequence(series, ordered_sequence_limit)),
        event_ids_in_order=("event_id", lambda series: _json_list(series, ordered_sequence_limit)),
        raw_event_row_indices=("raw_event_row_index", lambda series: _json_list(series, ordered_sequence_limit, ints=True)),
    ).reset_index()

    incidents = incidents.merge(sequence_frame, on="incident_group_id", how="left")
    incidents["incident_duration_seconds"] = (
        incidents["incident_end_time"] - incidents["incident_start_time"]
    ).dt.total_seconds().fillna(0.0)
    incidents["incident_id"] = incidents["incident_group_id"].map(lambda value: f"incident_{int(value):09d}")
    incidents["incident_start_date"] = incidents["incident_start_time"].dt.date.astype("string")

    ordered_columns = [
        "incident_id",
        "actor_key",
        "primary_source_ip_address",
        "incident_start_time",
        "incident_end_time",
        "incident_duration_seconds",
        "event_count",
        "distinct_event_names",
        "distinct_event_sources",
        "distinct_regions",
        "error_event_count",
        "success_event_count",
        "first_event_name",
        "last_event_name",
        "top_event_name",
        "contains_console_login",
        "contains_recon_like_api",
        "contains_privilege_change_api",
        "contains_resource_creation_api",
        "resource_types_seen",
        "user_agents_seen",
        "ordered_event_name_sequence",
        "ordered_event_source_sequence",
        "event_ids_in_order",
        "raw_event_row_indices",
        "incident_start_date",
    ]
    return incidents[ordered_columns].sort_values(
        ["incident_start_time", "actor_key", "primary_source_ip_address", "incident_id"],
        kind="mergesort",
        na_position="last",
    ).reset_index(drop=True)


def _first_non_null(series: pd.Series) -> Any:
    values = series.dropna()
    return values.iloc[0] if not values.empty else pd.NA


def _last_non_null(series: pd.Series) -> Any:
    values = series.dropna()
    return values.iloc[-1] if not values.empty else pd.NA


def _top_mode(series: pd.Series) -> Any:
    values = series.dropna()
    return values.mode().iloc[0] if not values.empty else pd.NA


def _mode_or_na(series: pd.Series) -> Any:
    values = series.dropna()
    return values.mode().iloc[0] if not values.empty else pd.NA


def _merge_pipe_values(series: pd.Series) -> Any:
    values: set[str] = set()
    for item in series.dropna():
        values.update(part for part in str(item).split("|") if part)
    return "|".join(sorted(values)) if values else pd.NA


def _join_unique(series: pd.Series, limit: int) -> Any:
    values = sorted(set(series.dropna().astype(str)))
    return "|".join(values[:limit]) if values else pd.NA


def _truncate_pipe_sequence(series: pd.Series, limit: int) -> Any:
    values = series.dropna().astype(str).tolist()
    return "|".join(values[:limit]) if values else pd.NA


def _json_list(series: pd.Series, limit: int, ints: bool = False) -> str:
    values = series.dropna().tolist()[:limit]
    if ints:
        values = [int(value) for value in values]
    else:
        values = [str(value) for value in values]
    return json.dumps(values)
