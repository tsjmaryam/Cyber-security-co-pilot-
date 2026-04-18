from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from src.ingest import RawRecord
from src.normalize import normalize_records


def _raw_record(record: dict, index: int = 0) -> RawRecord:
    return RawRecord(
        source_file_path="demo/file.json",
        source_file_name="file.json",
        record_index_in_file=index,
        ingest_ts_utc=datetime(2025, 1, 1, tzinfo=timezone.utc),
        record=record,
    )


def test_normalize_records_derives_presence_states_and_resource_summary():
    frame = normalize_records(
        [
            _raw_record(
                {
                    "eventID": "evt-1",
                    "eventTime": "2025-01-01T00:00:00Z",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "CreateAccessKey",
                    "readOnly": "false",
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/demo",
                        "accessKeyId": "",
                        "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2025-01-01T00:00:00Z"}},
                    },
                    "sourceIPAddress": None,
                    "userAgent": "  console  ",
                    "requestParameters": {"userName": "demo"},
                    "resources": [
                        {"type": "AWS::IAM::AccessKey", "ARN": "arn:1", "accountId": "123"},
                        {"type": "AWS::IAM::User", "ARN": "arn:2", "accountId": "123"},
                    ],
                }
            )
        ]
    )

    row = frame.iloc[0]
    assert row["event_time_epoch_ms"] == 1735689600000
    assert bool(row["read_only"]) is False
    assert bool(row["session_mfa_authenticated"]) is True
    assert bool(row["success"]) is True
    assert bool(row["is_error"]) is False
    assert row["user_agent"] == "console"
    assert row["access_key_id_presence_state"] == "empty"
    assert bool(row["missing_access_key_id"]) is True
    assert row["source_ip_address_presence_state"] == "null"
    assert bool(row["missing_source_ip_address"]) is True
    assert row["resource_count"] == 2
    assert row["resource_types_concat"] == "AWS::IAM::AccessKey|AWS::IAM::User"


def test_normalize_records_handles_invalid_timestamp_and_error_code():
    frame = normalize_records(
        [
            _raw_record(
                {
                    "eventID": "evt-2",
                    "eventTime": "not-a-time",
                    "eventSource": "signin.amazonaws.com",
                    "eventName": "ConsoleLogin",
                    "readOnly": True,
                    "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
                    "sourceIPAddress": "203.0.113.5",
                    "errorCode": "AccessDenied",
                }
            )
        ]
    )

    row = frame.iloc[0]
    assert pd.isna(row["event_time"])
    assert pd.isna(row["event_time_epoch_ms"])
    assert bool(row["success"]) is False
    assert bool(row["is_error"]) is True
