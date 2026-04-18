from __future__ import annotations

from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class EvidenceRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None:
        logger.debug("Fetching evidence package incident_id=%s", incident_id)
        query = """
        SELECT evidence_package_id, incident_id, summary_json, provenance_json, raw_refs_json, created_at
        FROM evidence_packages
        WHERE incident_id = %s
        ORDER BY created_at DESC, evidence_package_id DESC
        LIMIT 1
        """
        return _fetch_one(self._connection_factory, query, (incident_id,), context=f"incident_id={incident_id}")


def _fetch_one(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...], context: str | None = None) -> dict[str, Any] | None:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            logger.debug("Evidence query finished found=%s %s", row is not None, context or "")
            return dict(row) if row is not None else None
