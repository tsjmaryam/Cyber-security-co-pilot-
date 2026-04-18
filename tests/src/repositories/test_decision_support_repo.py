from __future__ import annotations

from src.repositories.decision_support_repo import DecisionSupportResultsRepository


def test_save_and_fetch_latest_decision_support_result(
    repository_connection_factory,
    seeded_incident,
    policy_version,
):
    repo = DecisionSupportResultsRepository(repository_connection_factory)
    repo.save_decision_support_result(
        seeded_incident,
        result={
            "decision_support_result": {
                "incident_id": seeded_incident,
                "recommended_action": {"action_id": "collect_more_evidence"},
            },
            "validation": {"schema_valid": True},
            "llm_trace": [{"step": "none"}],
        },
        policy_version=policy_version,
    )

    fetched = repo.fetch_latest_decision_support_result(seeded_incident)

    assert fetched is not None
    assert fetched["incident_id"] == seeded_incident
    assert fetched["result_json"]["recommended_action"]["action_id"] == "collect_more_evidence"
    assert fetched["policy_version"] == policy_version
