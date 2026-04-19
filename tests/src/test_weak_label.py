from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.weak_label import apply_weak_labels, load_label_rules


def test_load_label_rules_applies_defaults(tmp_path: Path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text("weights:\n  recon_activity: 1.5\n", encoding="utf-8")

    rules = load_label_rules(rules_path)

    assert rules["weights"]["recon_activity"] == 1.5
    assert rules["thresholds"] == {}
    assert rules["label_threshold"] == 1


def test_apply_weak_labels_scores_and_serializes_reasons():
    incidents = pd.DataFrame(
        [
            {
                "incident_id": "incident_1",
                "actor_key": "arn:aws:iam::123456789012:root",
                "error_event_count": 4,
                "success_event_count": 0,
                "event_count": 5,
                "incident_duration_seconds": 60,
                "distinct_event_names": 8,
                "contains_recon_like_api": True,
                "contains_privilege_change_api": True,
                "contains_resource_creation_api": False,
                "contains_console_login": True,
                "ordered_event_source_sequence": "signin.amazonaws.com > iam.amazonaws.com > ec2.amazonaws.com",
            },
            {
                "incident_id": "incident_2",
                "actor_key": "arn:aws:iam::123456789012:user/demo",
                "error_event_count": 0,
                "success_event_count": 3,
                "event_count": 3,
                "incident_duration_seconds": 600,
                "distinct_event_names": 2,
                "contains_recon_like_api": False,
                "contains_privilege_change_api": False,
                "contains_resource_creation_api": False,
                "contains_console_login": False,
                "ordered_event_source_sequence": "s3.amazonaws.com",
            },
        ]
    )
    rules = {
        "thresholds": {
            "high_failure_ratio": 0.5,
            "min_failure_events": 3,
            "high_event_count": 5,
            "short_incident_seconds": 120,
            "high_distinct_event_names": 6,
        },
        "weights": {
            "console_login": 1.0,
            "recon_activity": 1.0,
            "privilege_change": 1.0,
            "root_actor": 1.0,
            "high_failure_ratio": 1.0,
            "failure_burst": 1.0,
            "event_burst": 1.0,
            "broad_surface_area": 1.0,
            "iam_sequence": 1.0,
            "ec2_sequence": 1.0,
            "recon_plus_privilege": 1.0,
            "root_plus_privilege": 1.0,
        },
        "label_threshold": 3,
    }

    labeled, report = apply_weak_labels(incidents, rules)

    assert labeled.loc[0, "weak_label_suspicious"] == 1
    assert labeled.loc[1, "weak_label_suspicious"] == 0
    reasons = json.loads(labeled.loc[0, "weak_label_reasons_json"])
    assert {item["rule"] for item in reasons} >= {"console_login", "recon_activity", "privilege_change", "root_actor"}
    assert report["incident_count"] == 2
    assert report["positive_count"] == 1
    assert report["rule_hits"]["iam_sequence"] == 1

