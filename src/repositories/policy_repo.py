from __future__ import annotations

from typing import Any, Callable


class PolicyRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def fetch_policy_snapshot(self, policy_version: str | None = None) -> dict[str, Any] | None:
        if policy_version is None:
            query = """
            SELECT policy_version, policy_json, created_at
            FROM policy_snapshots
            ORDER BY created_at DESC
            LIMIT 1
            """
            params: tuple[Any, ...] = ()
        else:
            query = """
            SELECT policy_version, policy_json, created_at
            FROM policy_snapshots
            WHERE policy_version = %s
            """
            params = (policy_version,)
        return _fetch_one(self._connection_factory, query, params)


def _fetch_one(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            return dict(row) if row is not None else None
