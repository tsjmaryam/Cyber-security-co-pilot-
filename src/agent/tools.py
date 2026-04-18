from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .context import AgentRepositoryBundle


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class AgentTool:
    name: str
    description: str
    handler: ToolHandler


@dataclass
class AgentRuntimeState:
    repositories: AgentRepositoryBundle
    decision_support_service: Any
    incident_id: str
    policy_version: str | None = None
    cache: dict[str, Any] = field(default_factory=dict)
    decision_support_source: str | None = None

    def build_tools(self) -> dict[str, AgentTool]:
        return {
            "load_incident": AgentTool(
                name="load_incident",
                description="Load the incident record and core identifiers for the current incident.",
                handler=self._load_incident,
            ),
            "load_evidence_package": AgentTool(
                name="load_evidence_package",
                description="Load the latest evidence package from Postgres, including summary JSON and provenance.",
                handler=self._load_evidence_package,
            ),
            "load_detector_result": AgentTool(
                name="load_detector_result",
                description="Load the latest detector score, risk band, signals, labels, and retrieved patterns.",
                handler=self._load_detector_result,
            ),
            "load_coverage_assessment": AgentTool(
                name="load_coverage_assessment",
                description="Load completeness state, missing sources, and executed coverage checks.",
                handler=self._load_coverage_assessment,
            ),
            "load_decision_support": AgentTool(
                name="load_decision_support",
                description="Load the latest stored decision-support result for the incident if one already exists.",
                handler=self._load_decision_support,
            ),
            "generate_decision_support": AgentTool(
                name="generate_decision_support",
                description="Generate and persist a fresh decision-support result when one is missing or stale.",
                handler=self._generate_decision_support,
            ),
        }

    def context_summary(self) -> dict[str, bool]:
        return {
            "has_incident": self.cache.get("incident") is not None,
            "has_evidence_package": self.cache.get("evidence_package") is not None,
            "has_detector_result": self.cache.get("detector_result") is not None,
            "has_coverage_assessment": self.cache.get("coverage_assessment") is not None,
            "has_decision_support_result": self.cache.get("decision_support_result") is not None,
        }

    def _load_incident(self, _: dict[str, Any]) -> dict[str, Any]:
        if "incident" not in self.cache:
            incident = self.repositories.fetch_incident(self.incident_id)
            if incident is None:
                raise ValueError(f"Incident not found: {self.incident_id}")
            self.cache["incident"] = incident
        return self.cache["incident"]

    def _load_evidence_package(self, _: dict[str, Any]) -> dict[str, Any]:
        if "evidence_package" not in self.cache:
            self.cache["evidence_package"] = self.repositories.fetch_latest_evidence_package(self.incident_id)
        return {"evidence_package": self.cache["evidence_package"]}

    def _load_detector_result(self, _: dict[str, Any]) -> dict[str, Any]:
        if "detector_result" not in self.cache:
            self.cache["detector_result"] = self.repositories.fetch_latest_detector_result(self.incident_id)
        return {"detector_result": self.cache["detector_result"]}

    def _load_coverage_assessment(self, _: dict[str, Any]) -> dict[str, Any]:
        if "coverage_assessment" not in self.cache:
            self.cache["coverage_assessment"] = self.repositories.fetch_latest_coverage_assessment(self.incident_id)
        return {"coverage_assessment": self.cache["coverage_assessment"]}

    def _load_decision_support(self, _: dict[str, Any]) -> dict[str, Any]:
        if "decision_support_result" not in self.cache:
            stored = self.repositories.fetch_latest_decision_support_result(self.incident_id)
            self.cache["decision_support_result"] = stored
            if stored is not None:
                self.decision_support_source = "database"
        return {"decision_support_result": self.cache["decision_support_result"]}

    def _generate_decision_support(self, _: dict[str, Any]) -> dict[str, Any]:
        generated = self.decision_support_service.generate_for_incident(
            self.incident_id,
            policy_version=self.policy_version,
        )
        self.cache["decision_support_result"] = generated
        self.decision_support_source = "generated"
        return {"decision_support_result": generated}
