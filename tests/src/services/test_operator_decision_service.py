from src.services.coverage_review_service import CoverageReviewAppService
from src.services.operator_decision_service import OperatorDecisionAppService


class FakeOperatorBundle:
    def __init__(self):
        self.saved_decisions = []
        self.saved_events = []

    def fetch_incident(self, incident_id: str):
        return {
            "incident_id": incident_id,
            "title": "Stored incident",
            "summary": "Stored summary",
            "primary_actor": {"actor_key": "actor-1"},
            "entities": {"primary_source_ip_address": "1.2.3.4"},
            "event_sequence": ["ConsoleLogin", "AttachUserPolicy"],
        }

    def fetch_latest_evidence_package(self, incident_id: str):
        return {"summary_json": {"event_sequence": ["ConsoleLogin", "AttachUserPolicy"]}}

    def fetch_latest_detector_result(self, incident_id: str):
        return {
            "risk_score": 0.82,
            "risk_band": "high",
            "top_signals_json": [{"label": "High failure ratio"}],
            "counter_signals_json": [],
        }

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return {
            "completeness_level": "medium",
            "incompleteness_reasons_json": ["Network telemetry was not checked."],
            "checks_json": [{"name": "network_logs", "status": "not_checked"}],
            "missing_sources_json": ["network_logs"],
        }

    def fetch_latest_decision_support_result(self, incident_id: str):
        return {
            "result_json": {
                "recommended_action": {
                    "action_id": "reset_credentials",
                    "label": "Reset credentials",
                    "requires_human_approval": True,
                },
                "alternative_actions": [
                    {"action_id": "collect_more_evidence", "label": "Collect more evidence"},
                    {"action_id": "escalate_to_expert", "label": "Escalate to expert"},
                ],
                "completeness_assessment": {
                    "level": "medium",
                    "warning": "This recommendation may be incomplete.",
                    "reasons": ["Network telemetry was not checked."],
                },
            }
        }

    def save_operator_decision(self, **kwargs):
        self.saved_decisions.append(kwargs)

    def save_review_event(self, **kwargs):
        self.saved_events.append(kwargs)

    def fetch_latest_operator_decision(self, incident_id: str):
        return self.saved_decisions[-1] if self.saved_decisions else None


class FakeDecisionSupportGenerator:
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None):
        raise AssertionError("Stored decision support should have been reused.")


def _make_service():
    bundle = FakeOperatorBundle()
    coverage_review = CoverageReviewAppService(bundle, FakeDecisionSupportGenerator())
    return bundle, OperatorDecisionAppService(bundle, coverage_review)


def test_operator_can_approve_recommendation_with_snapshot():
    bundle, service = _make_service()
    result = service.approve_recommendation(
        "INC-OP-1",
        actor={"user_id": "operator-1"},
        rationale="The current risk justifies the recommended action.",
    )
    assert result["decision_type"] == "approve_recommendation"
    assert result["chosen_action"]["action_id"] == "reset_credentials"
    assert bundle.saved_decisions[-1]["selected_from"] == "recommended"
    assert bundle.saved_decisions[-1]["coverage_review"]["recommendation_may_be_incomplete"] is True


def test_operator_can_choose_alternative():
    bundle, service = _make_service()
    result = service.choose_alternative(
        "INC-OP-2",
        action_id="collect_more_evidence",
        actor={"user_id": "operator-2"},
        rationale="I want more evidence before taking a disruptive action.",
        used_double_check=True,
    )
    assert result["decision_type"] == "choose_alternative"
    assert result["chosen_action"]["action_id"] == "collect_more_evidence"
    assert bundle.saved_decisions[-1]["selected_from"] == "alternative"
    assert bundle.saved_decisions[-1]["used_double_check"] is True


def test_request_more_analysis_logs_double_check_event():
    bundle, service = _make_service()
    result = service.request_more_analysis(
        "INC-OP-3",
        actor={"user_id": "operator-3"},
        rationale="Network telemetry is still missing.",
    )
    assert result["decision_type"] == "request_more_analysis"
    assert bundle.saved_events[-1]["event_type"] == "double_check_requested"
    assert bundle.saved_decisions[-1]["selected_from"] == "double_check"
    assert bundle.saved_decisions[-1]["chosen_action_id"] == "collect_more_evidence"
