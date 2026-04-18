from __future__ import annotations

import json
from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class IncidentReportRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def save_report(
        self,
        incident_id: str,
        report_kind: str,
        summary: dict[str, Any],
        html_content: str,
        source_decision_type: str | None = None,
    ) -> None:
        logger.info(
            "Persisting incident report incident_id=%s report_kind=%s source_decision_type=%s",
            incident_id,
            report_kind,
            source_decision_type,
        )
        query = """
        INSERT INTO incident_reports (incident_id, report_kind, source_decision_type, summary_json, html_content)
        VALUES (%s, %s, %s, %s::jsonb, %s)
        """
        params = (
            incident_id,
            report_kind,
            source_decision_type,
            json.dumps(summary),
            html_content,
        )
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()

    def fetch_latest_report(self, incident_id: str, report_kind: str = "approval_summary") -> dict[str, Any] | None:
        logger.debug("Fetching latest incident report incident_id=%s report_kind=%s", incident_id, report_kind)
        query = """
        SELECT incident_id, report_kind, source_decision_type, summary_json, html_content, created_at
        FROM incident_reports
        WHERE incident_id = %s AND report_kind = %s
        ORDER BY created_at DESC, incident_report_id DESC
        LIMIT 1
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id, report_kind))
                row = cur.fetchone()
                return dict(row) if row is not None else None
