from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from src.logging_utils import get_logger
from .mcp_client import McpCyberContextClient, McpClientError
from .context import AgentRepositoryBundle
from src.services.decision_support_app_service import DecisionSupportAppService
from src.services.dtos import DecisionSupportPayloadDTO, CoverageRecordDTO, DetectorRecordDTO, EvidenceRecordDTO, IncidentRecordDTO

logger = get_logger(__name__)


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class AgentTool:
    name: str
    description: str
    handler: ToolHandler


@dataclass
class AgentRuntimeState:
    repositories: AgentRepositoryBundle
    decision_support_service: "DecisionSupportGenerator"
    incident_id: str
    policy_version: str | None = None
    mcp_client: McpCyberContextClient | None = None
    cache: dict[str, Any] = field(default_factory=dict)
    decision_support_source: str | None = None

    def build_tools(self) -> dict[str, AgentTool]:
        tools = {
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
        if self.mcp_client and self.mcp_client.enabled:
            tools["load_mcp_cyber_context"] = AgentTool(
                name="load_mcp_cyber_context",
                description="Search the MCP cyber knowledge base for relevant ATT&CK techniques, threats, and mitigations related to the current incident.",
                handler=self._load_mcp_cyber_context,
            )
        return tools

    def context_summary(self) -> dict[str, bool]:
        return {
            "has_incident": self.cache.get("incident") is not None,
            "has_evidence_package": self.cache.get("evidence_package") is not None,
            "has_detector_result": self.cache.get("detector_result") is not None,
            "has_coverage_assessment": self.cache.get("coverage_assessment") is not None,
            "has_decision_support_result": self.cache.get("decision_support_result") is not None,
            "has_mcp_cyber_context": self.cache.get("mcp_cyber_context") is not None,
        }

    def _load_incident(self, _: dict[str, Any]) -> dict[str, Any]:
        if "incident" not in self.cache:
            logger.debug("Agent tool load_incident cache_miss incident_id=%s", self.incident_id)
            incident = self.repositories.fetch_incident(self.incident_id)
            if incident is None:
                raise ValueError(f"Incident not found: {self.incident_id}")
            self.cache["incident"] = IncidentRecordDTO.from_record(incident)
        else:
            logger.debug("Agent tool load_incident cache_hit incident_id=%s", self.incident_id)
        return self.cache["incident"]

    def _load_evidence_package(self, _: dict[str, Any]) -> dict[str, Any]:
        if "evidence_package" not in self.cache:
            logger.debug("Agent tool load_evidence_package cache_miss incident_id=%s", self.incident_id)
            self.cache["evidence_package"] = EvidenceRecordDTO.from_record(self.repositories.fetch_latest_evidence_package(self.incident_id))
        else:
            logger.debug("Agent tool load_evidence_package cache_hit incident_id=%s", self.incident_id)
        return {"evidence_package": self.cache["evidence_package"]}

    def _load_detector_result(self, _: dict[str, Any]) -> dict[str, Any]:
        if "detector_result" not in self.cache:
            logger.debug("Agent tool load_detector_result cache_miss incident_id=%s", self.incident_id)
            result = self.repositories.fetch_latest_detector_result(self.incident_id)
            self.cache["detector_result"] = DetectorRecordDTO.from_record(result) if result is not None else None
        else:
            logger.debug("Agent tool load_detector_result cache_hit incident_id=%s", self.incident_id)
        return {"detector_result": self.cache["detector_result"]}

    def _load_coverage_assessment(self, _: dict[str, Any]) -> dict[str, Any]:
        if "coverage_assessment" not in self.cache:
            logger.debug("Agent tool load_coverage_assessment cache_miss incident_id=%s", self.incident_id)
            result = self.repositories.fetch_latest_coverage_assessment(self.incident_id)
            self.cache["coverage_assessment"] = CoverageRecordDTO.from_record(result) if result is not None else None
        else:
            logger.debug("Agent tool load_coverage_assessment cache_hit incident_id=%s", self.incident_id)
        return {"coverage_assessment": self.cache["coverage_assessment"]}

    def _load_decision_support(self, _: dict[str, Any]) -> dict[str, Any]:
        if "decision_support_result" not in self.cache:
            logger.debug("Agent tool load_decision_support cache_miss incident_id=%s", self.incident_id)
            stored = self.repositories.fetch_latest_decision_support_result(self.incident_id)
            self.cache["decision_support_result"] = DecisionSupportPayloadDTO.from_payload(stored)
            if stored is not None:
                self.decision_support_source = "database"
        else:
            logger.debug("Agent tool load_decision_support cache_hit incident_id=%s", self.incident_id)
        return {"decision_support_result": self.cache["decision_support_result"]}

    def _generate_decision_support(self, _: dict[str, Any]) -> dict[str, Any]:
        logger.info("Agent tool generate_decision_support incident_id=%s policy_version=%s", self.incident_id, self.policy_version)
        generated = self.decision_support_service.generate_for_incident(
            self.incident_id,
            policy_version=self.policy_version,
        )
        self.cache["decision_support_result"] = DecisionSupportPayloadDTO.from_payload(generated)
        self.decision_support_source = "generated"
        return {"decision_support_result": generated}

    def _load_mcp_cyber_context(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.mcp_client is None or not self.mcp_client.enabled:
            return {"mcp_cyber_context": []}
        query = str(payload.get("query") or "").strip()
        limit = int(payload.get("limit") or 5)
        if not query:
            query = self._default_mcp_query()
        logger.info("Agent tool load_mcp_cyber_context incident_id=%s query=%s", self.incident_id, query)
        try:
            rows = self.mcp_client.search(query=query, limit=limit)
        except McpClientError as exc:
            logger.warning("Agent MCP cyber context failed incident_id=%s error=%s", self.incident_id, exc)
            rows = []
        self.cache["mcp_cyber_context"] = rows
        return {"mcp_cyber_context": rows}

    def _default_mcp_query(self) -> str:
        parts: list[str] = []
        incident = self.cache.get("incident")
        detector = self.cache.get("detector_result")
        evidence = self.cache.get("evidence_package")
        if incident is not None:
            parts.extend([incident.title or "", incident.summary or ""])
            parts.extend(incident.event_sequence or [])
        if detector is not None:
            parts.extend(str(label) for label in detector.detector_labels)
            parts.extend(str(pattern) for pattern in detector.retrieved_patterns)
        if evidence is not None:
            summary = evidence.summary_json or {}
            parts.extend(str(item.get("title")) for item in summary.get("domain_terms", []) if isinstance(item, dict))
        return " ".join(part for part in parts if part)


class DecisionSupportGenerator(Protocol):
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]: ...
