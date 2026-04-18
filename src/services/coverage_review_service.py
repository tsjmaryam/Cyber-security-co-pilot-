from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from decision_support.completeness import build_completeness_assessment, build_review_candidates


COVERAGE_CATEGORIES = ("login", "identity", "network", "resource_activity")

CATEGORY_KEYWORDS = {
    "login": ("login", "console", "signin", "auth"),
    "identity": ("identity", "iam", "role", "credential", "sts", "access_key", "user"),
    "network": ("network", "vpc", "flow", "ip", "dns", "traffic"),
    "resource_activity": ("resource", "ec2", "instance", "s3", "bucket", "lambda", "kms", "database"),
}


class CoverageReviewRepositoryBundle(Protocol):
    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_decision_support_result(self, incident_id: str) -> dict[str, Any] | None: ...


class DecisionSupportGenerator(Protocol):
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]: ...


@dataclass
class CoverageReviewAppService:
    repositories: CoverageReviewRepositoryBundle
    decision_support_service: DecisionSupportGenerator

    def build_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]:
        incident_record = self.repositories.fetch_incident(incident_id)
        evidence_record = self.repositories.fetch_latest_evidence_package(incident_id)
        detector_record = self.repositories.fetch_latest_detector_result(incident_id)
        coverage_record = self.repositories.fetch_latest_coverage_assessment(incident_id)
        decision_support_record = self.repositories.fetch_latest_decision_support_result(incident_id)

        if incident_record is None:
            raise ValueError(f"Incident not found: {incident_id}")
        if detector_record is None:
            raise ValueError(f"Detector result not found: {incident_id}")
        if coverage_record is None:
            raise ValueError(f"Coverage assessment not found: {incident_id}")

        decision_support_result = _extract_decision_support_payload(decision_support_record)
        if decision_support_result is None:
            decision_support_result = self.decision_support_service.generate_for_incident(
                incident_id,
                policy_version=policy_version,
            )
        return build_coverage_review(
            incident_record=incident_record,
            evidence_record=evidence_record,
            detector_record=detector_record,
            coverage_record=coverage_record,
            decision_support_result=decision_support_result,
        )


def build_coverage_review(
    incident_record: dict[str, Any],
    evidence_record: dict[str, Any] | None,
    detector_record: dict[str, Any],
    coverage_record: dict[str, Any],
    decision_support_result: dict[str, Any],
) -> dict[str, Any]:
    ds_payload = _extract_decision_support_payload(decision_support_result) or {}
    recommended_action = dict(ds_payload.get("recommended_action") or {})
    completeness_assessment = dict(ds_payload.get("completeness_assessment") or {})
    if not completeness_assessment:
        completeness = build_completeness_assessment(_coverage_input(coverage_record))
        completeness_assessment = {
            "level": completeness.level.value,
            "warning": completeness.warning,
            "reasons": completeness.reasons,
        }
    review_candidates = build_review_candidates(_coverage_input(coverage_record))
    coverage_by_category = build_coverage_status_by_category(coverage_record)
    risk_note = build_decision_risk_note(recommended_action, completeness_assessment)
    return {
        "incident_id": incident_record["incident_id"],
        "incident_summary": build_incident_summary(incident_record, detector_record, evidence_record),
        "recommended_action": recommended_action,
        "alternative_actions": list(ds_payload.get("alternative_actions") or []),
        "coverage_status_by_category": coverage_by_category,
        "completeness": completeness_assessment,
        "recommendation_may_be_incomplete": bool(completeness_assessment.get("warning")),
        "decision_risk_note": risk_note,
        "what_could_change_the_decision": build_decision_change_hints(
            coverage_record=coverage_record,
            detector_record=detector_record,
            recommended_action=recommended_action,
            review_candidates=review_candidates,
        ),
        "double_check": {
            "available": True,
            "prompt": "Double check missing branches before taking disruptive action.",
            "candidates": review_candidates,
        },
    }


def build_incident_summary(
    incident_record: dict[str, Any],
    detector_record: dict[str, Any],
    evidence_record: dict[str, Any] | None,
) -> dict[str, Any]:
    summary_json = dict(evidence_record.get("summary_json") or {}) if evidence_record else {}
    event_sequence = list(incident_record.get("event_sequence") or summary_json.get("event_sequence") or [])
    return {
        "title": incident_record.get("title") or summary_json.get("title") or f"Incident {incident_record['incident_id']}",
        "summary": incident_record.get("summary") or summary_json.get("summary") or "Stored incident context",
        "risk_band": detector_record.get("risk_band"),
        "risk_score": detector_record.get("risk_score"),
        "top_signals": list(detector_record.get("top_signals_json") or []),
        "event_sequence": event_sequence,
        "primary_actor": incident_record.get("primary_actor"),
        "entities": incident_record.get("entities"),
    }


def build_coverage_status_by_category(coverage_record: dict[str, Any]) -> list[dict[str, Any]]:
    checks = list(coverage_record.get("checks_json") or [])
    missing_sources = list(coverage_record.get("missing_sources_json") or [])
    statuses = []
    for category in COVERAGE_CATEGORIES:
        relevant_checks = [check for check in checks if _matches_category(check.get("name", ""), category)]
        relevant_sources = [source for source in missing_sources if _matches_category(source, category)]
        if not relevant_checks and not relevant_sources:
            continue
        statuses.append(
            {
                "category": category,
                "status": _aggregate_category_status(relevant_checks, relevant_sources),
                "checks": relevant_checks,
                "missing_sources": relevant_sources,
            }
        )
    return statuses


def build_decision_risk_note(recommended_action: dict[str, Any], completeness_assessment: dict[str, Any]) -> str:
    warning = completeness_assessment.get("warning")
    if not warning:
        return "Coverage appears sufficient for the current recommendation."
    label = str(recommended_action.get("label") or recommended_action.get("action_id") or "the current action").lower()
    if recommended_action.get("requires_human_approval"):
        return f"{warning} {label.capitalize()} should be reviewed carefully because it is a disruptive action."
    return f"{warning} Review missing checks before relying on {label}."


def build_decision_change_hints(
    coverage_record: dict[str, Any],
    detector_record: dict[str, Any],
    recommended_action: dict[str, Any],
    review_candidates: list[str],
) -> list[str]:
    hints: list[str] = []
    for source in coverage_record.get("missing_sources_json") or []:
        hints.append(f"If {source} shows additional suspicious activity, the recommended action may need to change.")
    for candidate in review_candidates[:3]:
        hints.append(f"Completing {candidate.lower()} could confirm or weaken the current recommendation.")
    if recommended_action.get("requires_human_approval"):
        hints.append("If the missing checks do not support elevated misuse, a lower-disruption alternative may be safer.")
    if detector_record.get("counter_signals_json"):
        hints.append("Counter-signals may justify a less disruptive response after review.")
    return _dedupe(hints)[:5]


def _aggregate_category_status(relevant_checks: list[dict[str, Any]], relevant_sources: list[str]) -> str:
    if any(check.get("status") == "checked_signal_found" for check in relevant_checks):
        return "checked_signal_found"
    if any(check.get("status") == "checked_no_signal" for check in relevant_checks):
        return "checked_no_signal"
    if any(check.get("status") == "data_unavailable" for check in relevant_checks) or relevant_sources:
        return "data_unavailable" if not any(check.get("status") == "not_checked" for check in relevant_checks) else "not_checked"
    if any(check.get("status") == "not_checked" for check in relevant_checks):
        return "not_checked"
    return "unknown"


def _matches_category(value: str, category: str) -> bool:
    normalized = str(value).lower().replace("-", "_")
    return any(token in normalized for token in CATEGORY_KEYWORDS[category])


def _coverage_input(coverage_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "completeness_level": coverage_record["completeness_level"],
        "incompleteness_reasons": list(coverage_record.get("incompleteness_reasons_json") or []),
        "checks": list(coverage_record.get("checks_json") or []),
        "missing_sources": list(coverage_record.get("missing_sources_json") or []),
    }


def _extract_decision_support_payload(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result is None:
        return None
    if "recommended_action" in result or "alternative_actions" in result:
        return result
    if "decision_support_result" in result:
        return result["decision_support_result"]
    return result.get("result_json")


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
