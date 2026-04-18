from __future__ import annotations

import json
from typing import Any, Callable


class DecisionSupportResultsRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def save_decision_support_result(self, incident_id: str, result: dict[str, Any], policy_version: str | None) -> None:
        query = """
        INSERT INTO decision_support_results (incident_id, result_json, validation_json, llm_trace_json, policy_version)
        VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb, %s)
        """
        params = (
            incident_id,
            json.dumps(result["decision_support_result"]),
            json.dumps(result["validation"]),
            json.dumps(result["llm_trace"]),
            policy_version,
        )
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()
