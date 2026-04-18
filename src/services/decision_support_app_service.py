from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from decision_support.service import generate_decision_support


class RepositoryBundle(Protocol):
    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_policy_snapshot(self, policy_version: str | None = None) -> dict[str, Any] | None: ...
    def save_decision_support_result(self, incident_id: str, result: dict[str, Any], policy_version: str | None) -> None: ...


@dataclass
class DecisionSupportAppService:
    repositories: RepositoryBundle

    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]:
        incident_record = self.repositories.fetch_incident(incident_id)
        evidence_record = self.repositories.fetch_latest_evidence_package(incident_id)
        detector_record = self.repositories.fetch_latest_detector_result(incident_id)
        coverage_record = self.repositories.fetch_latest_coverage_assessment(incident_id)
        policy_record = self.repositories.fetch_policy_snapshot(policy_version)

        if incident_record is None:
            raise ValueError(f"Incident not found: {incident_id}")
        if detector_record is None:
            raise ValueError(f"Detector result not found: {incident_id}")
        if coverage_record is None:
            raise ValueError(f"Coverage assessment not found: {incident_id}")
        if policy_record is None:
            raise ValueError("Policy snapshot not found.")

        inputs = assemble_decision_support_inputs(
            incident_record=incident_record,
            evidence_record=evidence_record,
            detector_record=detector_record,
            coverage_record=coverage_record,
            policy_record=policy_record,
        )
        result = generate_decision_support(**inputs)
        self.repositories.save_decision_support_result(incident_id, result, policy_record["policy_version"])
        return result


def assemble_decision_support_inputs(
    incident_record: dict[str, Any],
    evidence_record: dict[str, Any] | None,
    detector_record: dict[str, Any],
    coverage_record: dict[str, Any],
    policy_record: dict[str, Any],
) -> dict[str, Any]:
    summary_json = dict(evidence_record.get("summary_json") or {}) if evidence_record else {}
    incident = {
        "incident_id": incident_record["incident_id"],
        "title": incident_record.get("title") or summary_json.get("title") or f"Incident {incident_record['incident_id']}",
        "summary": incident_record.get("summary") or summary_json.get("summary") or "Stored incident context",
        "severity_hint": incident_record.get("severity_hint"),
        "start_time": _stringify(incident_record.get("start_time")),
        "end_time": _stringify(incident_record.get("end_time")),
        "primary_actor": incident_record.get("primary_actor"),
        "entities": incident_record.get("entities"),
        "event_sequence": list(incident_record.get("event_sequence") or summary_json.get("event_sequence") or []),
    }
    detector_output = {
        "risk_score": detector_record.get("risk_score"),
        "risk_band": detector_record.get("risk_band"),
        "top_signals": list(detector_record.get("top_signals_json") or []),
        "counter_signals": list(detector_record.get("counter_signals_json") or []),
        "detector_labels": list(detector_record.get("detector_labels_json") or []),
        "retrieved_patterns": list(detector_record.get("retrieved_patterns_json") or []),
        "data_sources_used": list(detector_record.get("data_sources_used_json") or []),
    }
    coverage = {
        "completeness_level": coverage_record["completeness_level"],
        "incompleteness_reasons": list(coverage_record.get("incompleteness_reasons_json") or []),
        "checks": list(coverage_record.get("checks_json") or []),
        "missing_sources": list(coverage_record.get("missing_sources_json") or []),
    }
    policy = dict(policy_record["policy_json"])
    knowledge_context = {
        "playbook_snippets": list(summary_json.get("playbook_snippets") or []),
        "domain_terms": list(summary_json.get("domain_terms") or []),
    }
    operator_context = dict(summary_json.get("operator_context") or {"operator_type": "non_expert"})
    return {
        "incident": incident,
        "detector_output": detector_output,
        "coverage": coverage,
        "policy": policy,
        "knowledge_context": knowledge_context,
        "operator_context": operator_context,
    }


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)
