from __future__ import annotations

from typing import Any

from src.agent.context import AgentRepositoryBundle, load_agent_context


def generate_mock_agent_response(
    repositories: AgentRepositoryBundle,
    decision_support_service,
    incident_id: str,
    user_query: str,
    policy_version: str | None,
    model: str,
    endpoint: str,
) -> dict[str, Any]:
    context = load_agent_context(repositories, incident_id)
    reasoning_trace: list[dict[str, Any]] = [
        {
            "step": 1,
            "thought": "Load incident context for a grounded answer.",
            "action": "load_incident",
            "status": "observed",
            "observation": {"incident_id": context.incident.incident_id, "title": context.incident.title},
        }
    ]

    decision_support = context.decision_support_result
    decision_support_source = "database"
    if decision_support is None:
        generated = decision_support_service.generate_for_incident(incident_id, policy_version=policy_version)
        from src.services.dtos import DecisionSupportPayloadDTO

        decision_support = DecisionSupportPayloadDTO.from_payload(generated)
        decision_support_source = "generated"
        reasoning_trace.append(
            {
                "step": 2,
                "thought": "No stored recommendation exists, so generate one deterministically.",
                "action": "generate_decision_support",
                "status": "observed",
                "observation": generated,
            }
        )
    else:
        reasoning_trace.append(
            {
                "step": 2,
                "thought": "Use the stored recommendation before answering.",
                "action": "load_decision_support",
                "status": "observed",
                "observation": {"decision_support_result": decision_support.to_dict()},
            }
        )

    if context.coverage_assessment is not None:
        reasoning_trace.append(
            {
                "step": 3,
                "thought": "Check completeness so the answer calls out blind spots.",
                "action": "load_coverage_assessment",
                "status": "observed",
                "observation": {"coverage_assessment": context.coverage_assessment.to_decision_support_input()},
            }
        )

    answer = _build_mock_answer(context=context, decision_support=decision_support)
    reasoning_trace.append(
        {
            "step": len(reasoning_trace) + 1,
            "thought": "Enough grounded context is available.",
            "action": "finish",
            "status": "finished",
        }
    )

    return {
        "incident_id": incident_id,
        "user_query": user_query,
        "answer": answer,
        "model": model,
        "endpoint": endpoint,
        "decision_support_source": decision_support_source,
        "context_summary": {
            "has_incident": True,
            "has_evidence_package": context.evidence_package is not None,
            "has_detector_result": context.detector_result is not None,
            "has_coverage_assessment": context.coverage_assessment is not None,
            "has_decision_support_result": decision_support is not None,
            "has_mcp_cyber_context": False,
        },
        "reasoning_trace": reasoning_trace,
        "raw_response": {"mock_mode": True},
    }


def _build_mock_answer(context, decision_support) -> str:
    incident_title = context.incident.title or context.incident.incident_id
    recommended_action = decision_support.recommended_action if decision_support is not None else {}
    action_label = recommended_action.get("label") or recommended_action.get("action_id") or "review the incident"
    risk_band = context.detector_result.risk_band if context.detector_result is not None else None
    completeness = context.coverage_assessment.completeness_level if context.coverage_assessment is not None else None
    missing_sources = context.coverage_assessment.missing_sources if context.coverage_assessment is not None else []

    parts = [f"For {incident_title}, the current recommended action is {action_label}."]
    if risk_band:
        parts.append(f"The detector currently rates the incident as {risk_band} risk.")
    if completeness:
        parts.append(f"Coverage completeness is {completeness}.")
    if missing_sources:
        parts.append(f"Missing sources still affecting the decision: {', '.join(missing_sources)}.")
    elif completeness in {"high", "complete"}:
        parts.append("No major missing sources are currently recorded.")
    return " ".join(parts)
