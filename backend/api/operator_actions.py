from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, Response

from backend.dependencies import as_http_exception, get_operator_decision_repositories, get_operator_decision_service
from backend.models import AlternativeActionRequest, IncidentReportResponse, OperatorActionRequest, OperatorActionResponse, OperatorHistoryResponse
from src.repositories.service_bundles import OperatorDecisionRepositoryBundle
from src.services.incident_report_service import IncidentReportService
from src.services.operator_decision_service import OperatorDecisionAppService

router = APIRouter(prefix="/incidents/{incident_id}", tags=["operator-actions"])


@router.get("/operator-history", response_model=OperatorHistoryResponse)
def get_operator_history(
    incident_id: str,
    repositories: OperatorDecisionRepositoryBundle = Depends(get_operator_decision_repositories),
) -> OperatorHistoryResponse:
    return OperatorHistoryResponse(
        latest_decision=repositories.fetch_latest_operator_decision(incident_id),
        recent_decisions=repositories.fetch_recent_operator_decisions(incident_id, limit=10),
        review_events=repositories.fetch_recent_review_events(incident_id, limit=10),
    )


@router.get("/report/latest", response_model=IncidentReportResponse)
def get_latest_report(
    incident_id: str,
    repositories: OperatorDecisionRepositoryBundle = Depends(get_operator_decision_repositories),
) -> IncidentReportResponse:
    report = repositories.fetch_latest_incident_report(incident_id)
    if report is None:
        raise as_http_exception(ValueError(f"Report not found: {incident_id}"))
    payload = report.get("summary_json", report)
    return IncidentReportResponse(report=payload)


@router.get("/report/latest/print", response_class=HTMLResponse)
def print_latest_report(
    incident_id: str,
    repositories: OperatorDecisionRepositoryBundle = Depends(get_operator_decision_repositories),
) -> HTMLResponse:
    report = repositories.fetch_latest_incident_report(incident_id)
    if report is None:
        raise as_http_exception(ValueError(f"Report not found: {incident_id}"))
    return HTMLResponse(content=str(report["html_content"]))


@router.get("/report/latest/pdf")
def download_latest_report_pdf(
    incident_id: str,
    repositories: OperatorDecisionRepositoryBundle = Depends(get_operator_decision_repositories),
) -> Response:
    report = repositories.fetch_latest_incident_report(incident_id)
    if report is None:
        raise as_http_exception(ValueError(f"Report not found: {incident_id}"))
    payload = report.get("summary_json", report)
    pdf_bytes = IncidentReportService().render_pdf(payload)
    filename = f"sentinel-report-{incident_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/approve", response_model=OperatorActionResponse)
def approve_recommendation(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.approve_recommendation(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/alternative", response_model=OperatorActionResponse)
def choose_alternative(
    incident_id: str,
    request: AlternativeActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.choose_alternative(
            incident_id=incident_id,
            action_id=request.action_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/escalate", response_model=OperatorActionResponse)
def escalate(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.escalate(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/double-check", response_model=OperatorActionResponse)
def request_more_analysis(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.request_more_analysis(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check or True,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)
