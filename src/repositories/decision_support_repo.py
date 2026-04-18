from __future__ import annotations

import json
from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class DecisionSupportResultsRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def save_decision_support_result(self, incident_id: str, result: dict[str, Any], policy_version: str | None) -> None:
        logger.info("Persisting decision support incident_id=%s policy_version=%s", incident_id, policy_version)
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

    def fetch_latest_decision_support_result(self, incident_id: str) -> dict[str, Any] | None:
        logger.debug("Fetching latest decision support incident_id=%s", incident_id)
        query = """
        SELECT incident_id, result_json, validation_json, llm_trace_json, policy_version, created_at
        FROM decision_support_results
        WHERE incident_id = %s
        ORDER BY created_at DESC, decision_support_result_id DESC
        LIMIT 1
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id,))
                row = cur.fetchone()
                logger.debug("Decision support query finished incident_id=%s found=%s", incident_id, row is not None)
                return dict(row) if row is not None else None
