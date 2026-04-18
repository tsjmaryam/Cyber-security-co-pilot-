from __future__ import annotations

from typing import Any, Callable


class DetectorRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None:
        query = """
        SELECT incident_id, risk_score, risk_band, top_signals_json, counter_signals_json, detector_labels_json,
               retrieved_patterns_json, data_sources_used_json, model_version, created_at
        FROM detector_results
        WHERE incident_id = %s
        ORDER BY created_at DESC, detector_result_id DESC
        LIMIT 1
        """
        return _fetch_one(self._connection_factory, query, (incident_id,))

    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None:
        query = """
        SELECT incident_id, completeness_level, incompleteness_reasons_json, checks_json, missing_sources_json, created_at
        FROM coverage_assessments
        WHERE incident_id = %s
        ORDER BY created_at DESC, coverage_assessment_id DESC
        LIMIT 1
        """
        return _fetch_one(self._connection_factory, query, (incident_id,))


def _fetch_one(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            return dict(row) if row is not None else None
