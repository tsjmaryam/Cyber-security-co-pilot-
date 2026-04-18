from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class AgentRepositoryBundle(Protocol):
    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_decision_support_result(self, incident_id: str) -> dict[str, Any] | None: ...


@dataclass
class AgentContextBundle:
    incident: dict[str, Any]
    evidence_package: dict[str, Any] | None
    detector_result: dict[str, Any] | None
    coverage_assessment: dict[str, Any] | None
    decision_support_result: dict[str, Any] | None


def load_agent_context(repositories: AgentRepositoryBundle, incident_id: str) -> AgentContextBundle:
    incident = repositories.fetch_incident(incident_id)
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")
    return AgentContextBundle(
        incident=incident,
        evidence_package=repositories.fetch_latest_evidence_package(incident_id),
        detector_result=repositories.fetch_latest_detector_result(incident_id),
        coverage_assessment=repositories.fetch_latest_coverage_assessment(incident_id),
        decision_support_result=repositories.fetch_latest_decision_support_result(incident_id),
    )
