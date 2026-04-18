from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import yaml


def load_flag_rules(path: str | Path) -> dict[str, set[str]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return {key: {str(item) for item in value} for key, value in payload.items()}


def derive_event_features(frame: pd.DataFrame, flag_rules: dict[str, set[str]]) -> pd.DataFrame:
    if frame.empty:
        return frame
    result = frame.sort_values(
        ["event_time", "source_file_name", "record_index_in_file", "event_id"],
        kind="mergesort",
        na_position="last",
    ).reset_index(drop=True)
    result["raw_event_row_index"] = result.index.astype("Int64")
    result["event_date"] = result["event_time"].dt.date.astype("string")
    result["event_hour_utc"] = result["event_time"].dt.hour.astype("Int64")
    result["event_day_of_week_utc"] = result["event_time"].dt.day_name().astype("string")
    result["event_month_utc"] = result["event_time"].dt.month.astype("Int64")
    result["is_weekend_utc"] = result["event_time"].dt.dayofweek.isin([5, 6]).astype("boolean")
    result["actor_key"] = _build_actor_keys(result).astype("string")
    result["session_key"] = _build_session_keys(result).astype("string")
    result["global_sort_key"] = _build_global_sort_keys(result).astype("string")
    result["actor_event_rank"] = _rank_within_group(result, "actor_key")
    result["session_event_rank"] = _rank_within_group(result, "session_key")
    result["ip_event_rank"] = _rank_within_group(result, "source_ip_address", null_bucket="UNKNOWN_IP")
    result = _add_session_deltas(result)
    result = _add_identity_flags(result)
    result = _add_behavioral_flags(result, flag_rules)
    result = _add_rolling_count_features(result)
    return result


def _build_actor_keys(frame: pd.DataFrame) -> pd.Series:
    return frame[["user_arn", "principal_id", "access_key_id", "source_ip_address"]].bfill(axis=1).iloc[:, 0].fillna(
        "UNKNOWN_ACTOR"
    )


def _build_session_keys(frame: pd.DataFrame) -> pd.Series:
    event_date = frame["event_time"].dt.date.astype("string").fillna("UNKNOWN_DATE")
    source_ip = frame["source_ip_address"].astype("string").fillna("UNKNOWN_IP")
    user_agent = frame["user_agent"].astype("string").fillna("UNKNOWN_UA")
    session_key = (source_ip + "|" + user_agent + "|" + event_date).astype("string")
    principal_mask = frame["principal_id"].notna()
    session_key = session_key.where(~principal_mask, frame["principal_id"].astype("string") + "|" + source_ip + "|" + event_date)
    user_arn_mask = frame["user_arn"].notna()
    session_key = session_key.where(~user_arn_mask, frame["user_arn"].astype("string") + "|" + source_ip + "|" + event_date)
    access_key_mask = frame["access_key_id"].notna()
    session_key = session_key.where(~access_key_mask, frame["access_key_id"].astype("string"))
    return session_key


def _build_global_sort_keys(frame: pd.DataFrame) -> pd.Series:
    epoch_ms = frame["event_time_epoch_ms"].fillna(-1).astype("Int64").astype(str).str.zfill(13)
    record_index = frame["record_index_in_file"].fillna(-1).astype("Int64").astype(str).str.zfill(9)
    event_id = frame["event_id"].fillna("NO_EVENT_ID").astype("string")
    return epoch_ms + "|" + frame["source_file_name"].astype("string") + "|" + record_index + "|" + event_id


def _rank_within_group(frame: pd.DataFrame, column: str, null_bucket: str | None = None) -> pd.Series:
    grouping = frame[column].fillna(null_bucket) if null_bucket is not None else frame[column]
    return frame.groupby(grouping, dropna=False).cumcount().add(1).astype("Int64")


def _add_session_deltas(frame: pd.DataFrame) -> pd.DataFrame:
    prev_event_time = frame.groupby("session_key", dropna=False)["event_time"].shift(1)
    prev_source = frame.groupby("session_key", dropna=False)["event_source"].shift(1)
    prev_name = frame.groupby("session_key", dropna=False)["event_name"].shift(1)
    frame["seconds_since_prev_session_event"] = (frame["event_time"] - prev_event_time).dt.total_seconds().round(3)
    frame["same_event_source_as_prev_session_event"] = (frame["event_source"] == prev_source).astype("boolean")
    frame["same_event_name_as_prev_session_event"] = (frame["event_name"] == prev_name).astype("boolean")
    return frame


def _add_identity_flags(frame: pd.DataFrame) -> pd.DataFrame:
    user_type = frame["user_type"].fillna("").str.lower()
    user_arn = frame["user_arn"].fillna("").str.lower()
    frame["is_root_user"] = (user_type.eq("root") | user_arn.str.endswith(":root")).astype("boolean")
    frame["is_assumed_role"] = (
        user_type.eq("assumedrole") | user_arn.str.contains(":assumed-role/", regex=False)
    ).astype("boolean")
    frame["is_iam_user"] = (user_type.eq("iamuser") | user_arn.str.contains(":user/", regex=False)).astype("boolean")
    frame["is_aws_service_call"] = (
        frame["invoked_by"].notna() | user_type.isin(["awsservice", "assumedrolebyservice", "service"])
    ).astype("boolean")
    return frame


def _add_behavioral_flags(frame: pd.DataFrame, rules: dict[str, set[str]]) -> pd.DataFrame:
    event_name = frame["event_name"].fillna("")
    event_source = frame["event_source"].fillna("")
    frame["is_console_login"] = event_name.isin(rules.get("console_login_event_names", set())).astype("boolean")
    frame["is_auth_related"] = event_name.isin(rules.get("auth_related_event_names", set())).astype("boolean")
    frame["is_s3_related"] = event_source.isin(rules.get("s3_event_sources", set())).astype("boolean")
    frame["is_iam_related"] = event_source.isin(rules.get("iam_event_sources", set())).astype("boolean")
    frame["is_ec2_related"] = event_source.isin(rules.get("ec2_event_sources", set())).astype("boolean")
    frame["is_recon_like_api"] = event_name.isin(rules.get("recon_event_names", set())).astype("boolean")
    frame["is_privilege_change_api"] = event_name.isin(rules.get("privilege_change_event_names", set())).astype("boolean")
    frame["is_resource_creation_api"] = event_name.isin(rules.get("resource_creation_event_names", set())).astype("boolean")
    frame["is_failed_api_call"] = frame["is_error"].astype("boolean")
    frame["is_successful_api_call"] = frame["success"].astype("boolean")
    return frame


def _add_rolling_count_features(frame: pd.DataFrame) -> pd.DataFrame:
    event_time_ns = frame["event_time"].astype("int64", copy=False)
    frame["actor_events_prev_5m"] = _rolling_group_counts(event_time_ns, frame["actor_key"], 300)
    frame["actor_events_prev_1h"] = _rolling_group_counts(event_time_ns, frame["actor_key"], 3600)
    frame["ip_events_prev_5m"] = _rolling_group_counts(event_time_ns, frame["source_ip_address"].fillna("UNKNOWN_IP"), 300)
    frame["ip_events_prev_1h"] = _rolling_group_counts(event_time_ns, frame["source_ip_address"].fillna("UNKNOWN_IP"), 3600)
    frame["same_event_name_prev_5m"] = _rolling_group_counts(event_time_ns, frame["event_name"].fillna("UNKNOWN_EVENT"), 300)
    frame["same_event_name_prev_1h"] = _rolling_group_counts(event_time_ns, frame["event_name"].fillna("UNKNOWN_EVENT"), 3600)
    frame["same_event_source_prev_5m"] = _rolling_group_counts(event_time_ns, frame["event_source"].fillna("UNKNOWN_SOURCE"), 300)
    frame["same_event_source_prev_1h"] = _rolling_group_counts(event_time_ns, frame["event_source"].fillna("UNKNOWN_SOURCE"), 3600)
    return frame


def _rolling_group_counts(event_times_ns: pd.Series, group_keys: pd.Series, window_seconds: int) -> pd.Series:
    result = np.zeros(len(event_times_ns), dtype=np.int64)
    helper = pd.DataFrame({"event_time_ns": event_times_ns, "group_key": group_keys, "row_index": np.arange(len(event_times_ns))})
    for _, group in helper.groupby("group_key", sort=False, dropna=False):
        times = group["event_time_ns"].to_numpy(dtype=np.int64)
        valid_mask = times != np.iinfo(np.int64).min
        group_result = np.zeros(len(group), dtype=np.int64)
        if valid_mask.any():
            valid_times = times[valid_mask]
            starts = np.searchsorted(valid_times, valid_times - (window_seconds * 1_000_000_000), side="left")
            group_result[np.where(valid_mask)[0]] = np.arange(len(valid_times)) - starts
        result[group["row_index"].to_numpy(dtype=np.int64)] = group_result
    return pd.Series(result, dtype="Int64")
