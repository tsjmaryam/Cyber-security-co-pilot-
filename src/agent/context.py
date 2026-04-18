from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from src.services.dtos import CoverageRecordDTO, DecisionSupportPayloadDTO, DetectorRecordDTO, EvidenceRecordDTO, IncidentRecordDTO


class AgentRepositoryBundle(Protocol):
    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_decision_support_result(self, incident_id: str) -> dict[str, Any] | None: ...


@dataclass
class AgentContextBundle:
    incident: IncidentRecordDTO
    evidence_package: EvidenceRecordDTO | None
    detector_result: DetectorRecordDTO | None
    coverage_assessment: CoverageRecordDTO | None
    decision_support_result: DecisionSupportPayloadDTO | None


def load_agent_context(repositories: AgentRepositoryBundle, incident_id: str) -> AgentContextBundle:
    incident = repositories.fetch_incident(incident_id)
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")
    return AgentContextBundle(
        incident=IncidentRecordDTO.from_record(incident),
        evidence_package=EvidenceRecordDTO.from_record(repositories.fetch_latest_evidence_package(incident_id)),
        detector_result=_optional_dto(DetectorRecordDTO, repositories.fetch_latest_detector_result(incident_id)),
        coverage_assessment=_optional_dto(CoverageRecordDTO, repositories.fetch_latest_coverage_assessment(incident_id)),
        decision_support_result=DecisionSupportPayloadDTO.from_payload(repositories.fetch_latest_decision_support_result(incident_id)),
    )


def _optional_dto(dto_cls, value):
    if value is None:
        return None
    return dto_cls.from_record(value)
