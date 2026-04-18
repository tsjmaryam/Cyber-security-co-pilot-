from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from src.build_incidents import build_incidents


def test_build_incidents_splits_on_gap_and_partition():
    base = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    events = pd.DataFrame(
        [
            {
                "event_time": base,
                "actor_key": "actor-a",
                "source_ip_address": "203.0.113.1",
                "global_sort_key": "001",
                "event_id": "evt-1",
                "event_name": "ConsoleLogin",
                "event_source": "signin.amazonaws.com",
                "aws_region": "us-east-1",
                "is_error": False,
                "success": True,
                "is_console_login": True,
                "is_recon_like_api": False,
                "is_privilege_change_api": False,
                "is_resource_creation_api": False,
                "resource_types_concat": pd.NA,
                "user_agent": "ua-1",
                "raw_event_row_index": 0,
            },
            {
                "event_time": base + timedelta(minutes=1),
                "actor_key": "actor-a",
                "source_ip_address": "203.0.113.1",
                "global_sort_key": "002",
                "event_id": "evt-2",
                "event_name": "CreateAccessKey",
                "event_source": "iam.amazonaws.com",
                "aws_region": "us-east-1",
                "is_error": False,
                "success": True,
                "is_console_login": False,
                "is_recon_like_api": False,
                "is_privilege_change_api": True,
                "is_resource_creation_api": True,
                "resource_types_concat": "AWS::IAM::AccessKey",
                "user_agent": "ua-1",
                "raw_event_row_index": 1,
            },
            {
                "event_time": base + timedelta(minutes=30),
                "actor_key": "actor-a",
                "source_ip_address": "203.0.113.1",
                "global_sort_key": "003",
                "event_id": "evt-3",
                "event_name": "ListUsers",
                "event_source": "iam.amazonaws.com",
                "aws_region": "us-east-1",
                "is_error": False,
                "success": True,
                "is_console_login": False,
                "is_recon_like_api": True,
                "is_privilege_change_api": False,
                "is_resource_creation_api": False,
                "resource_types_concat": pd.NA,
                "user_agent": "ua-2",
                "raw_event_row_index": 2,
            },
        ]
    )

    incidents = build_incidents(events, incident_gap_minutes=15, ordered_sequence_limit=10)

    assert len(incidents) == 2
    first = incidents.iloc[0]
    second = incidents.iloc[1]
    assert first["incident_id"] == "incident_000000001"
    assert first["event_count"] == 2
    assert bool(first["contains_console_login"]) is True
    assert bool(first["contains_privilege_change_api"]) is True
    assert first["ordered_event_name_sequence"] == "ConsoleLogin|CreateAccessKey"
    assert first["raw_event_row_indices"] == "[0, 1]"
    assert second["incident_id"] == "incident_000000002"
    assert second["event_count"] == 1
    assert second["top_event_name"] == "ListUsers"


def test_build_incidents_returns_empty_frame_for_empty_input():
    assert build_incidents(pd.DataFrame(), incident_gap_minutes=15, ordered_sequence_limit=5).empty
