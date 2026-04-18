from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from typing import Any


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any, fallback: str = "Unavailable") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


@dataclass
class IncidentReportService:
    def build_approval_report(
        self,
        *,
        incident_id: str,
        coverage_review: dict[str, Any],
        chosen_action: dict[str, Any],
        rationale: str | None,
        actor: dict[str, Any] | None,
        used_double_check: bool,
    ) -> dict[str, Any]:
        incident_summary = _as_record(coverage_review.get("incident_summary"))
        recommended_action = _as_record(coverage_review.get("recommended_action"))
        top_signals = _as_list(incident_summary.get("top_signals"))
        signal_lines = [
            _as_str(_as_record(item).get("label"), "Signal observed")
            for item in top_signals
        ]
        coverage_items = _as_list(coverage_review.get("coverage_status_by_category"))
        blind_spots = [
            f"{_as_str(_as_record(item).get('category'), 'coverage')}: {_as_str(_as_record(item).get('status'), 'unknown')}"
            for item in coverage_items
            if _as_str(_as_record(item).get("status"), "").lower() in {"not_checked", "data_unavailable", "unknown"}
        ]
        what_could_change = [_as_str(item, "") for item in _as_list(coverage_review.get("what_could_change_the_decision"))]
        what_could_change = [item for item in what_could_change if item]
        report = {
            "incident_id": incident_id,
            "title": _as_str(incident_summary.get("title"), f"Incident {incident_id}"),
            "severity": _as_str(incident_summary.get("risk_band"), "unknown").capitalize(),
            "summary": _as_str(incident_summary.get("summary"), "Incident summary unavailable."),
            "approved_action": {
                "action_id": _as_str(chosen_action.get("action_id"), "action"),
                "label": _as_str(chosen_action.get("label"), "Approved action"),
                "reason": _as_str(chosen_action.get("reason") or recommended_action.get("reason"), "No action rationale available."),
            },
            "operator_rationale": _as_str(rationale, "No operator rationale was provided."),
            "why_sentinel_is_concerned": signal_lines or ["Sentinel observed risk signals that justified review."],
            "blind_spots": blind_spots or [_as_str(coverage_review.get("decision_risk_note"), "No blind spots recorded.")],
            "what_could_change_the_decision": what_could_change,
            "used_double_check": used_double_check,
            "approved_by": _as_str(_as_record(actor).get("user_id") or _as_record(actor).get("service"), "Operator"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return {
            "summary": report,
            "html": self.render_html(report),
        }

    def render_html(self, report: dict[str, Any]) -> str:
        def bullets(items: list[str]) -> str:
            if not items:
                return "<p>None recorded.</p>"
            return "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in items) + "</ul>"

        approved_action = _as_record(report.get("approved_action"))
        return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Sentinel Approval Report {escape(_as_str(report.get("incident_id"), ""))}</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 40px; color: #122033; }}
      h1, h2 {{ margin-bottom: 8px; }}
      .meta {{ color: #546678; font-size: 14px; margin-bottom: 24px; }}
      .section {{ margin-top: 24px; }}
      .section p, li {{ line-height: 1.55; }}
      .pill {{ display: inline-block; padding: 6px 10px; border-radius: 999px; background: #edf4ef; color: #2f7d63; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
      @media print {{ body {{ margin: 24px; }} .print-note {{ display: none; }} }}
    </style>
  </head>
  <body>
    <div class="print-note">Use your browser's Save as PDF option to export this report.</div>
    <span class="pill">Sentinel approval report</span>
    <h1>{escape(_as_str(report.get("title"), "Incident report"))}</h1>
    <div class="meta">
      Issue #{escape(_as_str(report.get("incident_id"), ""))} · Severity: {escape(_as_str(report.get("severity"), ""))} · Generated {escape(_as_str(report.get("generated_at"), ""))}
    </div>

    <div class="section">
      <h2>What happened</h2>
      <p>{escape(_as_str(report.get("summary"), ""))}</p>
    </div>

    <div class="section">
      <h2>Approved action</h2>
      <p><strong>{escape(_as_str(approved_action.get("label"), ""))}</strong></p>
      <p>{escape(_as_str(approved_action.get("reason"), ""))}</p>
    </div>

    <div class="section">
      <h2>Why the operator took this action</h2>
      <p>{escape(_as_str(report.get("operator_rationale"), ""))}</p>
    </div>

    <div class="section">
      <h2>Why Sentinel was concerned</h2>
      {bullets([_as_str(item, "") for item in _as_list(report.get("why_sentinel_is_concerned")) if _as_str(item, "")])}
    </div>

    <div class="section">
      <h2>Known blind spots</h2>
      {bullets([_as_str(item, "") for item in _as_list(report.get("blind_spots")) if _as_str(item, "")])}
    </div>

    <div class="section">
      <h2>What could still change the decision</h2>
      {bullets([_as_str(item, "") for item in _as_list(report.get("what_could_change_the_decision")) if _as_str(item, "")])}
    </div>
  </body>
</html>"""
