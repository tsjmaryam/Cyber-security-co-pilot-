from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from src.logging_utils import get_logger
from .coverage_review_service import CoverageReviewAppService

logger = get_logger(__name__)


class OperatorDecisionRepositoryBundle(Protocol):
    def save_operator_decision(self, **kwargs) -> None: ...
    def save_review_event(self, **kwargs) -> None: ...
    def fetch_latest_operator_decision(self, incident_id: str) -> dict[str, Any] | None: ...


@dataclass
class OperatorDecisionAppService:
    repositories: OperatorDecisionRepositoryBundle
    coverage_review_service: CoverageReviewAppService

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
        return {
            "incident_id": incident_id,
            "decision_type": "approve_recommendation",
            "chosen_action": recommended,
            "used_double_check": used_double_check,
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
