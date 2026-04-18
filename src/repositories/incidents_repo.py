from __future__ import annotations

from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class IncidentsRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None:
        logger.debug("Fetching incident incident_id=%s", incident_id)
        query = """
        SELECT incident_id, title, summary, severity_hint, start_time, end_time, primary_actor, entities, event_sequence
        FROM incidents
        WHERE incident_id = %s
        """
        return _fetch_one(self._connection_factory, query, (incident_id,), context=f"incident_id={incident_id}")


def _fetch_one(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...], context: str | None = None) -> dict[str, Any] | None:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            logger.debug("Incident query finished found=%s %s", row is not None, context or "")
            return dict(row) if row is not None else None
