from __future__ import annotations

import psycopg

from src.repositories.policy_repo import PolicyRepository


def test_fetch_policy_snapshot_by_version_and_latest(repository_connection_factory, repository_test_dsn, policy_version):
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO policy_snapshots (policy_version, policy_json)
                VALUES (%s, %s::jsonb)
                """,
                ("zzz-latest-policy", '{"allowed_actions":["reset_credentials"]}'),
            )
        conn.commit()

    repo = PolicyRepository(repository_connection_factory)
    exact = repo.fetch_policy_snapshot(policy_version)
    latest = repo.fetch_policy_snapshot()

    assert exact is not None
    assert exact["policy_version"] == policy_version
    assert latest is not None
    assert latest["policy_version"] in {policy_version, "zzz-latest-policy"}

    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM policy_snapshots WHERE policy_version = %s", ("zzz-latest-policy",))
        conn.commit()
