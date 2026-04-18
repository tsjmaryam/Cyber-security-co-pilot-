from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from src.derive_features import derive_event_features


def test_derive_event_features_builds_identity_flags_and_rolling_counts():
    base = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    frame = pd.DataFrame(
        [
            {
                "event_time": pd.Timestamp(base),
                "event_time_epoch_ms": int(base.timestamp() * 1000),
                "source_file_name": "a.json",
                "record_index_in_file": 0,
                "event_id": "evt-1",
                "user_arn": "arn:aws:iam::123456789012:user/demo",
                "principal_id": "AIDA1",
                "access_key_id": pd.NA,
                "source_ip_address": "203.0.113.10",
                "user_agent": "console",
                "user_type": "IAMUser",
                "invoked_by": pd.NA,
                "event_name": "ConsoleLogin",
                "event_source": "signin.amazonaws.com",
                "success": True,
                "is_error": False,
            },
            {
                "event_time": pd.Timestamp(base + timedelta(minutes=1)),
                "event_time_epoch_ms": int((base + timedelta(minutes=1)).timestamp() * 1000),
                "source_file_name": "a.json",
                "record_index_in_file": 1,
                "event_id": "evt-2",
                "user_arn": "arn:aws:iam::123456789012:user/demo",
                "principal_id": "AIDA1",
                "access_key_id": pd.NA,
                "source_ip_address": "203.0.113.10",
                "user_agent": "console",
                "user_type": "IAMUser",
                "invoked_by": pd.NA,
                "event_name": "ListUsers",
                "event_source": "iam.amazonaws.com",
                "success": True,
                "is_error": False,
            },
            {
                "event_time": pd.Timestamp(base + timedelta(minutes=2)),
                "event_time_epoch_ms": int((base + timedelta(minutes=2)).timestamp() * 1000),
                "source_file_name": "b.json",
                "record_index_in_file": 0,
                "event_id": "evt-3",
                "user_arn": "arn:aws:iam::123456789012:root",
                "principal_id": pd.NA,
                "access_key_id": "AKIA123",
                "source_ip_address": "203.0.113.10",
                "user_agent": "cli",
                "user_type": "Root",
                "invoked_by": "ec2.amazonaws.com",
                "event_name": "CreateAccessKey",
                "event_source": "iam.amazonaws.com",
                "success": False,
                "is_error": True,
            },
        ]
    )
    rules = {
        "console_login_event_names": {"ConsoleLogin"},
        "auth_related_event_names": {"ConsoleLogin"},
        "s3_event_sources": {"s3.amazonaws.com"},
        "iam_event_sources": {"iam.amazonaws.com"},
        "ec2_event_sources": {"ec2.amazonaws.com"},
        "recon_event_names": {"ListUsers"},
        "privilege_change_event_names": {"CreateAccessKey"},
        "resource_creation_event_names": {"CreateAccessKey"},
    }

    result = derive_event_features(frame, rules)

    assert result.loc[0, "actor_key"] == "arn:aws:iam::123456789012:user/demo"
    assert result.loc[0, "session_event_rank"] == 1
    assert result.loc[1, "session_event_rank"] == 2
    assert result.loc[1, "seconds_since_prev_session_event"] == 60.0
    assert bool(result.loc[1, "same_event_source_as_prev_session_event"]) is False
    assert bool(result.loc[0, "is_console_login"]) is True
    assert bool(result.loc[1, "is_recon_like_api"]) is True
    assert bool(result.loc[2, "is_privilege_change_api"]) is True
    assert bool(result.loc[2, "is_resource_creation_api"]) is True
    assert bool(result.loc[2, "is_root_user"]) is True
    assert bool(result.loc[2, "is_aws_service_call"]) is True
    assert result.loc[1, "actor_events_prev_5m"] == 1
    assert result.loc[2, "ip_events_prev_5m"] == 2
    assert result.loc[2, "same_event_name_prev_5m"] == 0


def test_derive_event_features_returns_empty_when_input_empty():
    assert derive_event_features(pd.DataFrame(), {}).empty
