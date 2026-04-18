from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from src.agent.openai_compat import OpenAICompatConfig
from src.agent.service import DecisionSupportAgent
from src.services.decision_support_app_service import DecisionSupportAppService
from src.train_model import train_incident_model
from src.weak_label import apply_weak_labels, load_label_rules


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class SequencedRequest:
    def __init__(self, contents: list[str]):
        self._contents = contents
        self.calls = 0

    def __call__(self, request):
        try:
            content = self._contents[self.calls]
        except IndexError as exc:
            raise AssertionError("Request sequence exhausted.") from exc
        self.calls += 1
        return FakeResponse({"choices": [{"message": {"content": content}}]})


@dataclass
class InMemoryPipelineBundle:
    incident_record: dict
    evidence_record: dict
    detector_record: dict
    coverage_record: dict
    policy_record: dict
    saved_result: dict | None = None
    saved_policy_version: str | None = None

    def fetch_incident(self, incident_id: str):
        return self.incident_record if incident_id == self.incident_record["incident_id"] else None

    def fetch_latest_evidence_package(self, incident_id: str):
        return self.evidence_record if incident_id == self.incident_record["incident_id"] else None

    def fetch_latest_detector_result(self, incident_id: str):
        return self.detector_record if incident_id == self.incident_record["incident_id"] else None

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return self.coverage_record if incident_id == self.incident_record["incident_id"] else None

    def fetch_policy_snapshot(self, policy_version=None):
        if policy_version is None or policy_version == self.policy_record["policy_version"]:
            return self.policy_record
        return None

    def save_decision_support_result(self, incident_id: str, result: dict, policy_version: str | None):
        assert incident_id == self.incident_record["incident_id"]
        self.saved_result = result
        self.saved_policy_version = policy_version

    def fetch_latest_decision_support_result(self, incident_id: str):
        if incident_id != self.incident_record["incident_id"]:
            return None
        return self.saved_result


def test_pipeline_flags_suspicious_incident_and_agent_reasons_over_decision_support(tmp_path: Path):
    incidents = pd.DataFrame([_incident_row(index, suspicious=index < 6) for index in range(12)])
    rules = load_label_rules(Path("configs/incident_label_rules.yaml"))
    labeled, _ = apply_weak_labels(incidents, rules)

    artifact_path = tmp_path / "incident_suspicion_model.joblib"
    _, scored = train_incident_model(labeled, artifact_path)

    suspicious_row = scored.sort_values("ml_suspicion_proba", ascending=False).iloc[0]
    assert suspicious_row["weak_label_suspicious"] == 1
    assert suspicious_row["ml_suspicion_pred"] == 1
    assert suspicious_row["ml_suspicion_proba"] >= 0.5

    reason_payload = json.loads(suspicious_row["weak_label_reasons_json"])
    detector_labels = [entry["rule"] for entry in reason_payload]
    top_signals = [{"label": entry["rule"], "weight": entry["weight"]} for entry in reason_payload[:5]]

    incident_id = str(suspicious_row["incident_id"])
    bundle = InMemoryPipelineBundle(
        incident_record={
            "incident_id": incident_id,
            "title": f"Suspicious incident {incident_id}",
            "summary": "Synthetic incident with recon and privilege-change activity.",
            "severity_hint": "high",
            "start_time": None,
            "end_time": None,
            "primary_actor": {"actor_key": suspicious_row["actor_key"]},
            "entities": {"primary_source_ip_address": suspicious_row["primary_source_ip_address"]},
            "event_sequence": str(suspicious_row["ordered_event_name_sequence"]).split(" > "),
        },
        evidence_record={
            "summary_json": {
                "event_sequence": str(suspicious_row["ordered_event_name_sequence"]).split(" > "),
                "playbook_snippets": ["Investigate whether the actor moved from reconnaissance into IAM privilege changes."],
                "domain_terms": [{"title": "recon_plus_privilege", "definition": "Recon followed by privilege change."}],
                "operator_context": {"operator_type": "non_expert"},
            }
        },
        detector_record={
            "risk_score": float(suspicious_row["ml_suspicion_proba"]),
            "risk_band": "high" if float(suspicious_row["ml_suspicion_proba"]) >= 0.7 else "medium",
            "top_signals_json": top_signals,
            "counter_signals_json": [],
            "detector_labels_json": detector_labels,
            "retrieved_patterns_json": ["Credential misuse signals detected"],
            "data_sources_used_json": ["incident_model", "weak_label_rules"],
        },
        coverage_record={
            "completeness_level": "medium",
            "incompleteness_reasons_json": ["Network telemetry has not been reviewed."],
            "checks_json": [{"name": "network_logs", "status": "not_checked"}],
            "missing_sources_json": ["network_logs"],
        },
        policy_record={
            "policy_version": "v1",
            "policy_json": {
                "allowed_actions": [
                    "reset_credentials",
                    "temporary_access_lock",
                    "continue_monitoring",
                    "escalate_to_expert",
                    "collect_more_evidence",
                ],
                "high_impact_actions": ["reset_credentials", "temporary_access_lock"],
                "default_non_expert_safe_action": "collect_more_evidence",
            },
        },
    )

    decision_support_service = DecisionSupportAppService(bundle)
    decision_support_result = decision_support_service.generate_for_incident(incident_id)
    assert decision_support_result["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"
    assert bundle.saved_result == decision_support_result
    assert bundle.saved_policy_version == "v1"

    request = SequencedRequest(
        [
            json.dumps({"thought": "Load the suspicious detector output first.", "action": "load_detector_result", "action_input": {}}),
            json.dumps({"thought": "Use the stored recommendation next.", "action": "load_decision_support", "action_input": {}}),
            json.dumps(
                {
                    "thought": "There is enough grounded evidence to answer.",
                    "action": "finish",
                    "final_answer": "The logs look suspicious because the incident model flagged high risk and the signals include reconnaissance plus privilege change activity. Decision support recommends resetting credentials while reviewing the missing network telemetry.",
                }
            ),
        ]
    )
    agent = DecisionSupportAgent(
        repositories=bundle,
        decision_support_service=decision_support_service,
        mcp_client=None,
        endpoint_config=OpenAICompatConfig(model="test-model", base_url="https://example.test/v1"),
    )
    agent_result = agent.respond(incident_id, "What should I do next and why?", request_fn=request)

    assert "logs look suspicious" in agent_result["answer"]
    assert "resetting credentials" in agent_result["answer"]
    assert agent_result["decision_support_source"] == "database"
    assert agent_result["context_summary"]["has_detector_result"] is True
    assert agent_result["context_summary"]["has_decision_support_result"] is True
    assert [step["action"] for step in agent_result["reasoning_trace"]] == [
        "load_detector_result",
        "load_decision_support",
        "finish",
    ]


def _incident_row(index: int, suspicious: bool) -> dict:
    incident_id = f"incident_{index:03d}"
    if suspicious:
        event_sequence = [
            "ConsoleLogin",
            "DescribeInstances",
            "ListUsers",
            "AttachUserPolicy",
            "CreateAccessKey",
        ]
        event_sources = [
            "signin.amazonaws.com",
            "ec2.amazonaws.com",
            "iam.amazonaws.com",
            "iam.amazonaws.com",
            "iam.amazonaws.com",
        ]
        return {
            "incident_id": incident_id,
            "incident_duration_seconds": 240 + index,
            "event_count": 22 + index,
            "distinct_event_names": 9,
            "distinct_event_sources": 3,
            "distinct_regions": 2,
            "error_event_count": 6,
            "success_event_count": 0,
            "contains_console_login": True,
            "contains_recon_like_api": True,
            "contains_privilege_change_api": True,
            "contains_resource_creation_api": False,
            "actor_key": f"arn:aws:iam::123456789012:root",
            "primary_source_ip_address": f"203.0.113.{10 + index}",
            "first_event_name": event_sequence[0],
            "last_event_name": event_sequence[-1],
            "top_event_name": "AttachUserPolicy",
            "ordered_event_source_sequence": " > ".join(event_sources),
            "ordered_event_name_sequence": " > ".join(event_sequence),
        }
    event_sequence = ["DescribeInstances", "GetCallerIdentity", "ListBuckets"]
    event_sources = ["ec2.amazonaws.com", "sts.amazonaws.com", "s3.amazonaws.com"]
    return {
        "incident_id": incident_id,
        "incident_duration_seconds": 1800 + index,
        "event_count": 4 + (index % 2),
        "distinct_event_names": 3,
        "distinct_event_sources": 3,
        "distinct_regions": 1,
        "error_event_count": 0,
        "success_event_count": 4 + (index % 2),
        "contains_console_login": False,
        "contains_recon_like_api": False,
        "contains_privilege_change_api": False,
        "contains_resource_creation_api": False,
        "actor_key": f"arn:aws:iam::123456789012:user/analyst-{index}",
        "primary_source_ip_address": f"198.51.100.{10 + index}",
        "first_event_name": event_sequence[0],
        "last_event_name": event_sequence[-1],
        "top_event_name": event_sequence[0],
        "ordered_event_source_sequence": " > ".join(event_sources),
        "ordered_event_name_sequence": " > ".join(event_sequence),
    }
