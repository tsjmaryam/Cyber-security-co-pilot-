from __future__ import annotations

from src.services.incident_report_service import IncidentReportService


def _coverage_review() -> dict:
    return {
        "incident_summary": {
            "title": "Unusual login with missing network branch",
            "risk_band": "high",
            "summary": "A user signed in, explored the environment, and changed access-related settings.",
            "top_signals": [
                {"label": "console_login"},
                {"label": "recon_activity"},
                {"label": "privilege_change"},
            ],
        },
        "coverage_status_by_category": [
            {"category": "network_logs", "status": "not_checked"},
            {"category": "device_context", "status": "data_unavailable"},
        ],
        "what_could_change_the_decision": [
            "Network telemetry could show follow-on activity.",
            "Device context could show whether this came from a known machine.",
        ],
        "decision_risk_note": "The recommendation may be incomplete because some evidence is missing.",
        "recommended_action": {
            "label": "Reset credentials",
            "reason": "The account may have been misused.",
        },
    }


def _chosen_action() -> dict:
    return {
        "action_id": "reset_credentials",
        "label": "Reset credentials",
        "reason": "Credential-focused containment is the safest next step.",
    }


def test_build_approval_report_shapes_summary_html_and_pdf():
    service = IncidentReportService()

    result = service.build_approval_report(
        incident_id="INC-REPORT-1",
        coverage_review=_coverage_review(),
        chosen_action=_chosen_action(),
        rationale="The combination of sign-in and privilege-related activity justifies immediate containment.",
        actor={"user_id": "operator-1"},
        used_double_check=True,
    )

    summary = result["summary"]
    html = result["html"]
    pdf = service.render_pdf(summary)

    assert summary["incident_id"] == "INC-REPORT-1"
    assert summary["title"] == "Unusual login with missing network branch"
    assert summary["severity"] == "High"
    assert summary["approved_action"]["label"] == "Reset credentials"
    assert summary["approved_by"] == "operator-1"
    assert summary["used_double_check"] is True
    assert "Someone signed in through the AWS console." in summary["why_sentinel_is_concerned"]
    assert "The account explored the environment before taking further action." in summary["why_sentinel_is_concerned"]
    assert "Network logs: Some important checks were not completed yet." in summary["blind_spots"]
    assert "Device context: Some evidence could not be checked because the data was unavailable." in summary["blind_spots"]

    assert "<h1>Unusual login with missing network branch</h1>" in html
    assert "Sentinel approval report" in html
    assert "Known blind spots" in html
    assert "Issue #INC-REPORT-1" in html

    assert pdf.startswith(b"%PDF-1.4")
    assert len(pdf) > 500


def test_render_html_escapes_operator_controlled_content():
    service = IncidentReportService()

    result = service.build_approval_report(
        incident_id="INC-REPORT-2",
        coverage_review=_coverage_review(),
        chosen_action={
            "action_id": "collect_more_evidence",
            "label": "Collect <more> evidence",
            "reason": "Wait for <script>alert('x')</script> more context.",
        },
        rationale="Operator noted <b>HTML-like</b> text.",
        actor={"user_id": "operator-2"},
        used_double_check=False,
    )

    html = result["html"]

    assert "Collect &lt;more&gt; evidence" in html
    assert "&lt;script&gt;alert" in html
    assert "Operator noted &lt;b&gt;HTML-like&lt;/b&gt; text." in html
    assert "<script>alert('x')</script>" not in html


class FakeLlmReportService:
    def generate_report(self, context: dict) -> dict:
        assert context["incident_id"] == "INC-REPORT-3"
        return {
            "summary": "LLM summary rewrite.",
            "approved_action_reason": "LLM action rationale.",
            "operator_rationale": "LLM operator rationale.",
            "why_sentinel_is_concerned": ["LLM concern"],
            "blind_spots": ["LLM blind spot"],
            "what_could_change_the_decision": ["LLM decision change"],
        }


def test_build_approval_report_can_be_enhanced_with_llm():
    service = IncidentReportService(llm_report_service=FakeLlmReportService())

    result = service.build_approval_report(
        incident_id="INC-REPORT-3",
        coverage_review=_coverage_review(),
        chosen_action=_chosen_action(),
        rationale="Original rationale.",
        actor={"user_id": "operator-3"},
        used_double_check=False,
    )

    summary = result["summary"]

    assert summary["summary"] == "LLM summary rewrite."
    assert summary["approved_action"]["reason"] == "LLM action rationale."
    assert summary["operator_rationale"] == "LLM operator rationale."
    assert summary["why_sentinel_is_concerned"] == ["LLM concern"]
    assert summary["blind_spots"] == ["LLM blind spot"]
    assert summary["what_could_change_the_decision"] == ["LLM decision change"]
    assert summary["draft_source"] == "openai"
