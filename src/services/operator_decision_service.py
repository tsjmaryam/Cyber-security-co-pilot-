from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from src.logging_utils import get_logger
from .incident_report_service import IncidentReportService
from .coverage_review_service import CoverageReviewAppService

logger = get_logger(__name__)


class OperatorDecisionRepositoryBundle(Protocol):
    def save_operator_decision(self, **kwargs) -> None: ...
    def save_review_event(self, **kwargs) -> None: ...
    def fetch_latest_operator_decision(self, incident_id: str) -> dict[str, Any] | None: ...
    def save_incident_report(self, **kwargs) -> None: ...
    def fetch_latest_incident_report(self, incident_id: str, report_kind: str = "approval_summary") -> dict[str, Any] | None: ...


@dataclass
class OperatorDecisionAppService:
    repositories: OperatorDecisionRepositoryBundle
    coverage_review_service: CoverageReviewAppService
    incident_report_service: IncidentReportService | None = None

    def approve_recommendation(
        self,
        incident_id: str,
        actor: dict[str, Any] | None = None,
        rationale: str | None = None,
        policy_version: str | None = None,
        used_double_check: bool = False,
    ) -> dict[str, Any]:
        logger.info("Recording operator approval incident_id=%s used_double_check=%s", incident_id, used_double_check)
        review = self.coverage_review_service.build_for_incident(incident_id, policy_version=policy_version)
        recommended = dict(review["recommended_action"])
        self.repositories.save_operator_decision(
            incident_id=incident_id,
            decision_type="approve_recommendation",
            selected_from="recommended",
            chosen_action_id=recommended.get("action_id"),
            chosen_action_label=recommended.get("label"),
            rationale=rationale,
            used_double_check=used_double_check,
            actor=actor,
            coverage_review=review,
            decision_support_result=_decision_support_snapshot(review),
        )
        report = self._save_approval_report(
            incident_id=incident_id,
            review=review,
            chosen_action=recommended,
            rationale=rationale,
            actor=actor,
            used_double_check=used_double_check,
            decision_type="approve_recommendation",
        )
        return {
            "incident_id": incident_id,
            "decision_type": "approve_recommendation",
            "chosen_action": recommended,
            "used_double_check": used_double_check,
            "report": report,
        }

    def choose_alternative(
        self,
        incident_id: str,
        action_id: str,
        actor: dict[str, Any] | None = None,
        rationale: str | None = None,
        policy_version: str | None = None,
        used_double_check: bool = False,
    ) -> dict[str, Any]:
        logger.info("Recording alternative choice incident_id=%s action_id=%s used_double_check=%s", incident_id, action_id, used_double_check)
        review = self.coverage_review_service.build_for_incident(incident_id, policy_version=policy_version)
        alternative = _select_action(review["alternative_actions"], action_id)
        if alternative is None:
            raise ValueError(f"Alternative action not found: {action_id}")
        self.repositories.save_operator_decision(
            incident_id=incident_id,
            decision_type="choose_alternative",
            selected_from="alternative",
            chosen_action_id=alternative.get("action_id"),
            chosen_action_label=alternative.get("label"),
            rationale=rationale,
            used_double_check=used_double_check,
            actor=actor,
            coverage_review=review,
            decision_support_result=_decision_support_snapshot(review),
        )
        return {
            "incident_id": incident_id,
            "decision_type": "choose_alternative",
            "chosen_action": alternative,
            "used_double_check": used_double_check,
        }

    def escalate(
        self,
        incident_id: str,
        actor: dict[str, Any] | None = None,
        rationale: str | None = None,
        policy_version: str | None = None,
        used_double_check: bool = False,
    ) -> dict[str, Any]:
        logger.info("Recording escalation incident_id=%s used_double_check=%s", incident_id, used_double_check)
        review = self.coverage_review_service.build_for_incident(incident_id, policy_version=policy_version)
        escalation_action = _select_action(review["alternative_actions"], "escalate_to_expert") or {
            "action_id": "escalate_to_expert",
            "label": "Escalate to expert",
        }
        self.repositories.save_operator_decision(
            incident_id=incident_id,
            decision_type="escalate",
            selected_from="manual",
            chosen_action_id=escalation_action.get("action_id"),
            chosen_action_label=escalation_action.get("label"),
            rationale=rationale,
            used_double_check=used_double_check,
            actor=actor,
            coverage_review=review,
            decision_support_result=_decision_support_snapshot(review),
        )
        return {
            "incident_id": incident_id,
            "decision_type": "escalate",
            "chosen_action": escalation_action,
            "used_double_check": used_double_check,
        }

    def request_more_analysis(
        self,
        incident_id: str,
        actor: dict[str, Any] | None = None,
        rationale: str | None = None,
        policy_version: str | None = None,
        used_double_check: bool = True,
    ) -> dict[str, Any]:
        logger.info("Recording more-analysis request incident_id=%s", incident_id)
        review = self.coverage_review_service.build_for_incident(incident_id, policy_version=policy_version)
        payload = {
            "coverage_review": review,
            "double_check_candidates": review["double_check"]["candidates"],
            "decision_risk_note": review["decision_risk_note"],
            "rationale": rationale,
        }
        self.repositories.save_review_event(
            incident_id=incident_id,
            event_type="double_check_requested",
            payload=payload,
            actor=actor,
        )
        self.repositories.save_operator_decision(
            incident_id=incident_id,
            decision_type="request_more_analysis",
            selected_from="double_check",
            chosen_action_id="collect_more_evidence",
            chosen_action_label="Collect more evidence",
            rationale=rationale,
            used_double_check=used_double_check,
            actor=actor,
            coverage_review=review,
            decision_support_result=_decision_support_snapshot(review),
        )
        return {
            "incident_id": incident_id,
            "decision_type": "request_more_analysis",
            "double_check_candidates": review["double_check"]["candidates"],
            "used_double_check": used_double_check,
        }

    def fetch_latest_report(self, incident_id: str, report_kind: str = "approval_summary") -> dict[str, Any] | None:
        return self.repositories.fetch_latest_incident_report(incident_id, report_kind=report_kind)

    def _save_approval_report(
        self,
        *,
        incident_id: str,
        review: dict[str, Any],
        chosen_action: dict[str, Any],
        rationale: str | None,
        actor: dict[str, Any] | None,
        used_double_check: bool,
        decision_type: str,
    ) -> dict[str, Any]:
        report_service = self.incident_report_service or IncidentReportService()
        rendered = report_service.build_approval_report(
            incident_id=incident_id,
            coverage_review=review,
            chosen_action=chosen_action,
            rationale=rationale,
            actor=actor,
            used_double_check=used_double_check,
        )
        self.repositories.save_incident_report(
            incident_id=incident_id,
            report_kind="approval_summary",
            source_decision_type=decision_type,
            summary=rendered["summary"],
            html_content=rendered["html"],
        )
        self.repositories.save_review_event(
            incident_id=incident_id,
            event_type="approval_report_generated",
            payload={
                "report_kind": "approval_summary",
                "generated_at": rendered["summary"]["generated_at"],
            },
            actor=actor,
        )
        return rendered["summary"]


def _select_action(actions: list[dict[str, Any]], action_id: str) -> dict[str, Any] | None:
    for action in actions:
        if action.get("action_id") == action_id:
            return dict(action)
    return None


def _decision_support_snapshot(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "recommended_action": review.get("recommended_action"),
        "alternative_actions": review.get("alternative_actions"),
        "completeness": review.get("completeness"),
        "decision_risk_note": review.get("decision_risk_note"),
    }
