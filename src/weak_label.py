from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import yaml


SEQUENCE_SERVICE_PATTERNS = {
    "has_iam_sequence": "iam.amazonaws.com",
    "has_sts_sequence": "sts.amazonaws.com",
    "has_ec2_sequence": "ec2.amazonaws.com",
}


def load_label_rules(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    payload.setdefault("weights", {})
    payload.setdefault("thresholds", {})
    payload.setdefault("label_threshold", 1)
    return payload


def apply_weak_labels(incidents: pd.DataFrame, rules: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    if incidents.empty:
        return incidents.copy(), {"incident_count": 0, "positive_count": 0, "positive_rate": 0.0, "rule_hits": {}}

    labeled = incidents.copy()
    thresholds = rules["thresholds"]
    weights = rules["weights"]

    labeled["actor_is_root"] = labeled["actor_key"].fillna("").str.contains(":root", regex=False)
    labeled["actor_is_assumed_role"] = labeled["actor_key"].fillna("").str.contains(":assumed-role/", regex=False)
    labeled["failure_ratio"] = (
        labeled["error_event_count"] / labeled["event_count"].replace({0: pd.NA})
    ).fillna(0.0)
    labeled["events_per_minute"] = (
        labeled["event_count"] / (labeled["incident_duration_seconds"].clip(lower=1.0) / 60.0)
    ).fillna(0.0)
    labeled["has_high_failure_ratio"] = (
        labeled["failure_ratio"].ge(float(thresholds["high_failure_ratio"]))
        & labeled["error_event_count"].ge(int(thresholds["min_failure_events"]))
    )
    labeled["has_failure_burst"] = (
        labeled["error_event_count"].ge(int(thresholds["min_failure_events"])) & labeled["success_event_count"].eq(0)
    )
    labeled["has_event_burst"] = labeled["event_count"].ge(int(thresholds["high_event_count"])) & labeled[
        "incident_duration_seconds"
    ].le(float(thresholds["short_incident_seconds"]))
    labeled["has_broad_surface_area"] = labeled["distinct_event_names"].ge(int(thresholds["high_distinct_event_names"]))
    labeled["has_recon_plus_privilege"] = (
        labeled["contains_recon_like_api"] & labeled["contains_privilege_change_api"]
    )
    labeled["has_recon_plus_resource_creation"] = (
        labeled["contains_recon_like_api"] & labeled["contains_resource_creation_api"]
    )
    labeled["has_privilege_plus_resource_creation"] = (
        labeled["contains_privilege_change_api"] & labeled["contains_resource_creation_api"]
    )
    labeled["has_root_plus_privilege"] = labeled["actor_is_root"] & labeled["contains_privilege_change_api"]

    ordered_sources = labeled["ordered_event_source_sequence"].fillna("")
    for column, token in SEQUENCE_SERVICE_PATTERNS.items():
        labeled[column] = ordered_sources.str.contains(token, regex=False)

    rule_columns = {
        "recon_activity": "contains_recon_like_api",
        "privilege_change": "contains_privilege_change_api",
        "resource_creation": "contains_resource_creation_api",
        "console_login": "contains_console_login",
        "root_actor": "actor_is_root",
        "assumed_role_actor": "actor_is_assumed_role",
        "high_failure_ratio": "has_high_failure_ratio",
        "failure_burst": "has_failure_burst",
        "event_burst": "has_event_burst",
        "broad_surface_area": "has_broad_surface_area",
        "iam_sequence": "has_iam_sequence",
        "sts_sequence": "has_sts_sequence",
        "ec2_sequence": "has_ec2_sequence",
        "recon_plus_privilege": "has_recon_plus_privilege",
        "recon_plus_resource_creation": "has_recon_plus_resource_creation",
        "privilege_plus_resource_creation": "has_privilege_plus_resource_creation",
        "root_plus_privilege": "has_root_plus_privilege",
    }

    labeled["weak_label_score"] = 0.0
    for rule_name, column in rule_columns.items():
        weight = float(weights.get(rule_name, 0))
        labeled["weak_label_score"] = labeled["weak_label_score"] + labeled[column].astype(float) * weight

    labeled["weak_label_suspicious"] = (
        labeled["weak_label_score"].ge(float(rules["label_threshold"]))
    ).astype(int)
    labeled["weak_label_reasons_json"] = labeled.apply(
        lambda row: _serialize_reasons(row, rule_columns, weights),
        axis=1,
    )

    report = {
        "incident_count": int(len(labeled)),
        "positive_count": int(labeled["weak_label_suspicious"].sum()),
        "positive_rate": round(float(labeled["weak_label_suspicious"].mean()), 6),
        "label_threshold": float(rules["label_threshold"]),
        "rule_hits": {
            name: int(labeled[column].sum()) for name, column in rule_columns.items()
        },
        "score_distribution": {
            "min": round(float(labeled["weak_label_score"].min()), 6),
            "median": round(float(labeled["weak_label_score"].median()), 6),
            "max": round(float(labeled["weak_label_score"].max()), 6),
        },
    }
    return labeled, report


def _serialize_reasons(row: pd.Series, rule_columns: dict[str, str], weights: dict[str, Any]) -> str:
    reasons = []
    for rule_name, column in rule_columns.items():
        if bool(row[column]):
            reasons.append({"rule": rule_name, "weight": float(weights.get(rule_name, 0.0))})
    return json.dumps(reasons)
