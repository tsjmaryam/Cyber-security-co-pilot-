from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from typing import Any

from src.logging_utils import get_logger

from .llm_report_service import LlmReportService

logger = get_logger(__name__)
SIGNAL_EXPLANATIONS: dict[str, str] = {
    "recon_activity": "The account explored the environment before taking further action.",
    "privilege_change": "Permissions or access levels changed during the incident.",
    "resource_creation": "New resources or infrastructure were created.",
    "console_login": "Someone signed in through the AWS console.",
    "root_actor": "The AWS root account was involved, which raises the impact of the activity.",
    "assumed_role_actor": "An assumed role was used, so the session may need extra tracing.",
    "high_failure_ratio": "A large share of the activity failed, which can indicate misuse or trial-and-error behavior.",
    "failure_burst": "There was a burst of failed activity in a short time window.",
    "event_burst": "A high number of actions happened in a short window.",
    "broad_surface_area": "The activity touched many different actions or services.",
    "iam_sequence": "The sequence included identity and access management actions.",
    "sts_sequence": "The sequence included temporary credential or role-assumption activity.",
    "ec2_sequence": "The activity included EC2 infrastructure actions.",
    "recon_plus_privilege": "The actor first explored the environment, then changed permissions.",
    "recon_plus_resource_creation": "The actor first explored the environment, then created resources.",
    "privilege_plus_resource_creation": "Permissions changed and new resources were created in the same incident.",
    "root_plus_privilege": "The root account was used together with permission-changing activity.",
}

COVERAGE_STATUS_EXPLANATIONS: dict[str, str] = {
    "not_checked": "Some important checks were not completed yet.",
    "data_unavailable": "Some evidence could not be checked because the data was unavailable.",
    "unknown": "Some parts of the incident still need review before the picture is complete.",
}


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any, fallback: str = "Unavailable") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _explain_signal(item: Any) -> str:
    record = _as_record(item)
    label = _as_str(record.get("label"), "Signal observed")
    return SIGNAL_EXPLANATIONS.get(label, label.replace("_", " ").capitalize())


def _explain_blind_spot(item: Any) -> str:
    row = _as_record(item)
    category = _as_str(row.get("category"), "coverage").replace("_", " ")
    status = _as_str(row.get("status"), "unknown").lower()
    explanation = COVERAGE_STATUS_EXPLANATIONS.get(status, "Some evidence is still incomplete.")
    return f"{category.capitalize()}: {explanation}"


@dataclass
class IncidentReportService:
    llm_report_service: LlmReportService | None = None

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
        signal_lines = [_explain_signal(item) for item in top_signals]
        coverage_items = _as_list(coverage_review.get("coverage_status_by_category"))
        blind_spots = [
            _explain_blind_spot(item)
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
            "operator_rationale": _as_str(rationale, "The operator approved this action without adding extra written rationale."),
            "why_sentinel_is_concerned": signal_lines or ["Sentinel observed risk signals that justified review."],
            "blind_spots": blind_spots or [_as_str(coverage_review.get("decision_risk_note"), "No blind spots recorded.")],
            "what_could_change_the_decision": what_could_change,
            "used_double_check": used_double_check,
            "approved_by": _as_str(_as_record(actor).get("user_id") or _as_record(actor).get("service"), "Operator"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        report = self._maybe_enhance_with_llm(report)
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

    def _maybe_enhance_with_llm(self, report: dict[str, Any]) -> dict[str, Any]:
        if self.llm_report_service is None:
            return report
        try:
            draft = self.llm_report_service.generate_report(report)
        except Exception:
            logger.exception("LLM approval report generation failed incident_id=%s", report.get("incident_id"))
            return report

        approved_action = _as_record(report.get("approved_action"))
        approved_action["reason"] = _as_str(draft.get("approved_action_reason"), approved_action.get("reason", ""))
        report["approved_action"] = approved_action
        report["summary"] = _as_str(draft.get("summary"), report.get("summary", ""))
        report["operator_rationale"] = _as_str(draft.get("operator_rationale"), report.get("operator_rationale", ""))

        concerns = _as_list(draft.get("why_sentinel_is_concerned"))
        if concerns:
            report["why_sentinel_is_concerned"] = concerns

        blind_spots = _as_list(draft.get("blind_spots"))
        if blind_spots:
            report["blind_spots"] = blind_spots

        decision_changes = _as_list(draft.get("what_could_change_the_decision"))
        if decision_changes:
            report["what_could_change_the_decision"] = decision_changes

        report["draft_source"] = "openai"
        return report

    def render_pdf(self, report: dict[str, Any]) -> bytes:
        lines = self._report_lines(report)
        return _build_simple_pdf(lines)

    def _report_lines(self, report: dict[str, Any]) -> list[str]:
        approved_action = _as_record(report.get("approved_action"))
        lines: list[str] = [
            "Sentinel Approval Report",
            "",
            f"Issue #{_as_str(report.get('incident_id'), '')}",
            f"Severity: {_as_str(report.get('severity'), '')}",
            f"Generated: {_as_str(report.get('generated_at'), '')}",
            "",
            "What happened",
            _as_str(report.get("summary"), ""),
            "",
            "Approved action",
            _as_str(approved_action.get("label"), ""),
            _as_str(approved_action.get("reason"), ""),
            "",
            "Why the action was taken",
            _as_str(report.get("operator_rationale"), ""),
            "",
            "Why Sentinel was concerned",
        ]
        lines.extend(f"- {_as_str(item, '')}" for item in _as_list(report.get("why_sentinel_is_concerned")) if _as_str(item, ""))
        lines.append("")
        lines.append("Known blind spots")
        lines.extend(f"- {_as_str(item, '')}" for item in _as_list(report.get("blind_spots")) if _as_str(item, ""))
        changes = [_as_str(item, "") for item in _as_list(report.get("what_could_change_the_decision")) if _as_str(item, "")]
        if changes:
            lines.append("")
            lines.append("What could still change the decision")
            lines.extend(f"- {item}" for item in changes)
        return lines


def _wrap_text(text: str, max_chars: int = 92) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return [""]
    words = stripped.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_simple_pdf(lines: list[str]) -> bytes:
    wrapped_lines: list[str] = []
    for line in lines:
        wrapped_lines.extend(_wrap_text(line))

    page_width = 612
    page_height = 792
    margin_left = 54
    margin_top = 62
    line_height = 16
    max_lines_per_page = 42
    pages = [wrapped_lines[i:i + max_lines_per_page] for i in range(0, len(wrapped_lines), max_lines_per_page)] or [[]]

    objects: list[bytes] = []

    def add_object(data: str | bytes) -> int:
        payload = data.encode("latin-1") if isinstance(data, str) else data
        objects.append(payload)
        return len(objects)

    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []

    for page_lines in pages:
        commands = ["BT", "/F1 11 Tf"]
        y = page_height - margin_top
        for line in page_lines:
            commands.append(f"1 0 0 1 {margin_left} {int(y)} Tm ({_escape_pdf_text(line)}) Tj")
            y -= line_height
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        content_id = add_object(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        content_ids.append(content_id)
        page_ids.append(0)

    kids_refs = " ".join(f"{obj_id} 0 R" for obj_id in page_ids if obj_id)
    pages_id = add_object("<< /Type /Pages /Kids [] /Count 0 >>")

    for index, content_id in enumerate(content_ids):
        page_id = add_object(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids[index] = page_id

    kids_refs = " ".join(f"{obj_id} 0 R" for obj_id in page_ids)
    objects[pages_id - 1] = (
        f"<< /Type /Pages /Kids [{kids_refs}] /Count {len(page_ids)} >>".encode("latin-1")
    )

    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii")
    )
    return bytes(output)
