from __future__ import annotations

import psycopg

from src.repositories.operator_decision_repo import OperatorDecisionRepository


def test_save_and_fetch_latest_operator_decision(repository_connection_factory, repository_test_dsn, seeded_incident):
    repo = OperatorDecisionRepository(repository_connection_factory)
    repo.save_operator_decision(
        incident_id=seeded_incident,
        decision_type="approve_recommendation",
        selected_from="recommended_action",
        chosen_action_id="reset_credentials",
        chosen_action_label="Reset credentials",
        rationale="Looks valid",
        used_double_check=True,
        actor={"user": "tester"},
        coverage_review={"recommendation_may_be_incomplete": True},
        decision_support_result={"recommended_action": {"action_id": "reset_credentials"}},
    )
    repo.save_review_event(
        incident_id=seeded_incident,
        event_type="double_check_requested",
        payload={"missing_sources": ["network_logs"]},
        actor={"user": "tester"},
    )

    decision = repo.fetch_latest_operator_decision(seeded_incident)

    assert decision is not None
    assert decision["decision_type"] == "approve_recommendation"
    assert decision["used_double_check"] is True
    assert decision["actor_json"]["user"] == "tester"

    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_type, payload_json FROM decision_review_events WHERE incident_id = %s ORDER BY decision_review_event_id DESC LIMIT 1",
                (seeded_incident,),
            )
            row = cur.fetchone()
    assert row[0] == "double_check_requested"
    assert row[1]["missing_sources"] == ["network_logs"]
