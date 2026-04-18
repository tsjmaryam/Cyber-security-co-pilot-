from src.services.coverage_review_service import CoverageReviewAppService, build_coverage_review


def test_build_coverage_review_emphasizes_incomplete_high_impact_recommendation():
    review = build_coverage_review(
        incident_record={
            "incident_id": "INC-REVIEW-1",
            "title": "Root activity",
            "summary": "Suspicious root activity",
            "primary_actor": {"actor_key": "root"},
            "entities": {"primary_source_ip_address": "1.2.3.4"},
            "event_sequence": ["ConsoleLogin", "AttachUserPolicy"],
        },
        evidence_record={
            "summary_json": {
                "event_sequence": ["ConsoleLogin", "AttachUserPolicy"],
            }
        },
        detector_record={
            "risk_score": 0.91,
            "risk_band": "high",
            "top_signals_json": [{"label": "root_actor"}],
            "counter_signals_json": [],
        },
        coverage_record={
            "completeness_level": "medium",
            "incompleteness_reasons_json": ["Network telemetry was not checked."],
            "checks_json": [
                {"name": "login_activity", "status": "checked_signal_found"},
                {"name": "network_logs", "status": "not_checked"},
                {"name": "iam_changes", "status": "checked_signal_found"},
            ],
            "missing_sources_json": ["network_logs"],
        },
        decision_support_result={
            "decision_support_result": {
                "recommended_action": {
                    "action_id": "reset_credentials",
                    "label": "Reset credentials",
                    "requires_human_approval": True,
                },
                "alternative_actions": [{"action_id": "collect_more_evidence", "label": "Collect more evidence"}],
                "completeness_assessment": {
                    "level": "medium",
                    "warning": "This recommendation may be incomplete.",
                    "reasons": ["Network telemetry was not checked."],
                },
            }
        },
    )
    assert review["recommendation_may_be_incomplete"] is True
    assert review["recommended_action"]["action_id"] == "reset_credentials"
    assert any(item["category"] == "network" and item["status"] == "not_checked" for item in review["coverage_status_by_category"])
    assert "disruptive action" in review["decision_risk_note"]
    assert review["double_check"]["available"] is True
    assert review["double_check"]["candidates"]
    assert any("network_logs" in item for item in review["what_could_change_the_decision"])


class FakeCoverageReviewBundle:
    def __init__(self):
        self.generated = None

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
            "completeness_level": "low",
            "incompleteness_reasons_json": ["Network telemetry was not checked."],
            "checks_json": [{"name": "network_logs", "status": "not_checked"}],
            "missing_sources_json": ["network_logs"],
        }

    def fetch_latest_decision_support_result(self, incident_id: str):
        return None


class FakeDecisionSupportGenerator:
    def __init__(self):
        self.calls = 0

    def generate_for_incident(self, incident_id: str, policy_version: str | None = None):
        self.calls += 1
        return {
            "decision_support_result": {
                "recommended_action": {
                    "action_id": "collect_more_evidence",
                    "label": "Collect more evidence",
                    "requires_human_approval": False,
                },
                "alternative_actions": [{"action_id": "escalate_to_expert", "label": "Escalate to expert"}],
                "completeness_assessment": {
                    "level": "low",
                    "warning": "This recommendation may be incomplete because key checks or sources are missing.",
                    "reasons": ["Missing source: network_logs"],
                },
            }
        }


def test_coverage_review_app_service_generates_decision_support_when_missing():
    bundle = FakeCoverageReviewBundle()
    generator = FakeDecisionSupportGenerator()
    service = CoverageReviewAppService(bundle, generator)
    review = service.build_for_incident("INC-REVIEW-2")
    assert generator.calls == 1
    assert review["recommended_action"]["action_id"] == "collect_more_evidence"
    assert review["recommendation_may_be_incomplete"] is True
    assert review["double_check"]["available"] is True
