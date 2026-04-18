from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pandas as pd
from pandas.api.types import is_object_dtype, is_string_dtype

from .ingest import RawRecord


SELECTED_FIELD_STATES = {
    "user_arn": ("userIdentity", "arn"),
    "access_key_id": ("userIdentity", "accessKeyId"),
    "source_ip_address": ("sourceIPAddress",),
    "user_agent": ("userAgent",),
    "request_parameters": ("requestParameters",),
    "resources": ("resources",),
}


def normalize_records(records: list[RawRecord]) -> pd.DataFrame:
    rows = [_normalize_record(item) for item in records]
    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame
    frame["event_time"] = pd.to_datetime(frame["event_time"], errors="coerce", utc=True)
    frame["event_time_epoch_ms"] = frame["event_time"].map(
        lambda value: pd.NA if pd.isna(value) else int(value.timestamp() * 1000)
    ).astype("Int64")
    frame["session_creation_date"] = pd.to_datetime(frame["session_creation_date"], errors="coerce", utc=True)
    frame["ingest_ts_utc"] = pd.to_datetime(frame["ingest_ts_utc"], utc=True)
    frame["read_only"] = frame["read_only"].map(_normalize_boolean).astype("boolean")
    frame["session_mfa_authenticated"] = frame["session_mfa_authenticated"].map(_normalize_boolean).astype("boolean")
    frame["success"] = (frame["error_code"].isna() | (frame["error_code"] == "")).astype("boolean")
    frame["is_error"] = (~frame["success"]).astype("boolean")
    frame["resource_count"] = frame["resource_count"].astype("Int64")
    for column in frame.columns:
        if is_object_dtype(frame[column]) or is_string_dtype(frame[column]):
            frame[column] = frame[column].map(_normalize_string)
    for selected in SELECTED_FIELD_STATES:
        state_column = f"{selected}_presence_state"
        frame[f"missing_{selected}"] = frame[state_column].isin(["absent", "null", "empty"]).astype("boolean")
    return frame


def _normalize_record(item: RawRecord) -> dict[str, Any]:
    record = item.record
    user_identity = _get_mapping(record, "userIdentity")
    session_context = _get_mapping(user_identity, "sessionContext")
    session_attributes = _get_mapping(session_context, "attributes")
    session_issuer = _get_mapping(session_context, "sessionIssuer")
    resources = record.get("resources")
    row: dict[str, Any] = {
        "source_file_path": item.source_file_path,
        "source_file_name": item.source_file_name,
        "record_index_in_file": item.record_index_in_file,
        "ingest_ts_utc": item.ingest_ts_utc.isoformat(),
        "event_id": record.get("eventID"),
        "event_version": record.get("eventVersion"),
        "event_time": record.get("eventTime"),
        "event_source": record.get("eventSource"),
        "event_name": record.get("eventName"),
        "event_type": record.get("eventType"),
        "api_version": record.get("apiVersion"),
        "aws_region": record.get("awsRegion"),
        "read_only": record.get("readOnly"),
        "recipient_account_id": record.get("recipientAccountId"),
        "shared_event_id": record.get("sharedEventID"),
        "vpc_endpoint_id": record.get("vpcEndpointId"),
        "user_type": user_identity.get("type"),
        "principal_id": user_identity.get("principalId"),
        "user_arn": user_identity.get("arn"),
        "user_account_id": user_identity.get("accountId"),
        "invoked_by": user_identity.get("invokedBy"),
        "access_key_id": user_identity.get("accessKeyId"),
        "username": user_identity.get("userName"),
        "session_mfa_authenticated": session_attributes.get("mfaAuthenticated"),
        "session_creation_date": session_attributes.get("creationDate"),
        "session_issuer_type": session_issuer.get("type"),
        "session_issuer_principal_id": session_issuer.get("principalId"),
        "session_issuer_arn": session_issuer.get("arn"),
        "session_issuer_account_id": session_issuer.get("accountId"),
        "session_issuer_username": session_issuer.get("userName"),
        "source_ip_address": record.get("sourceIPAddress"),
        "user_agent": record.get("userAgent"),
        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
        "request_parameters_json": _json_dumps(record.get("requestParameters")),
        "response_elements_json": _json_dumps(record.get("responseElements")),
        "additional_event_data_json": _json_dumps(record.get("additionalEventData")),
        "service_event_details_json": _json_dumps(record.get("serviceEventDetails")),
        "resources_json": _json_dumps(resources),
    }
    row.update(_resource_summary(resources))
    row.update(_selected_presence_states(record))
    return row


def _resource_summary(resources: Any) -> dict[str, Any]:
    if not isinstance(resources, list):
        return {
            "resource_count": 0 if resources == [] else pd.NA,
            "resource_types_concat": pd.NA,
            "resource_arns_concat": pd.NA,
            "resource_account_ids_concat": pd.NA,
        }
    types = sorted({str(item.get("type")).strip() for item in resources if isinstance(item, dict) and item.get("type")})
    arns = sorted({str(item.get("ARN")).strip() for item in resources if isinstance(item, dict) and item.get("ARN")})
    account_ids = sorted(
        {str(item.get("accountId")).strip() for item in resources if isinstance(item, dict) and item.get("accountId")}
    )
    return {
        "resource_count": len(resources),
        "resource_types_concat": "|".join(types) if types else pd.NA,
        "resource_arns_concat": "|".join(arns) if arns else pd.NA,
        "resource_account_ids_concat": "|".join(account_ids) if account_ids else pd.NA,
    }


def _selected_presence_states(record: dict[str, Any]) -> dict[str, str]:
    states: dict[str, str] = {}
    for output_name, path in SELECTED_FIELD_STATES.items():
        _, state = _extract_presence_state(record, path)
        states[f"{output_name}_presence_state"] = state
    return states


def _extract_presence_state(payload: Any, path: tuple[str, ...]) -> tuple[Any, str]:
    current = payload
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return pd.NA, "absent"
        current = current[key]
    if current is None:
        return current, "null"
    if isinstance(current, str) and current == "":
        return current, "empty"
    if isinstance(current, list) and len(current) == 0:
        return current, "empty"
    return current, "present"


def _get_mapping(payload: Mapping[str, Any] | None, key: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    value = payload.get(key)
    return value if isinstance(value, Mapping) else {}


def _json_dumps(value: Any) -> Any:
    if value is None:
        return pd.NA
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _normalize_string(value: Any) -> Any:
    if value is pd.NA or value is None:
        return pd.NA
    if isinstance(value, str):
        trimmed = value.strip()
        return trimmed if trimmed else pd.NA
    return value


def _normalize_boolean(value: Any) -> Any:
    if value is pd.NA or value is None:
        return pd.NA
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return pd.NA
