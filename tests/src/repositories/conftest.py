from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _resolve_dsn() -> str | None:
    for key in ("POSTGRES_DSN", "DATABASE_URL"):
        value = os.environ.get(key)
        if value:
            return value
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("POSTGRES_DSN="):
            return stripped.split("=", 1)[1]
        if stripped.startswith("DATABASE_URL="):
            return stripped.split("=", 1)[1]
    return None


@pytest.fixture(scope="session")
def repository_test_dsn() -> str:
    dsn = _resolve_dsn()
    if not dsn:
        pytest.skip("No POSTGRES_DSN or DATABASE_URL available for repository tests.")
    return dsn


@pytest.fixture(scope="session", autouse=True)
def repository_schema_ready(repository_test_dsn: str) -> None:
    schema_sql = (PROJECT_ROOT / "src" / "db" / "schema.sql").read_text(encoding="utf-8")
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        conn.commit()


@pytest.fixture
def repository_connection_factory(repository_test_dsn: str):
    def factory():
        return psycopg.connect(repository_test_dsn, row_factory=psycopg.rows.dict_row)

    return factory


@pytest.fixture
def seeded_incident(repository_test_dsn: str):
    incident_id = f"test-incident-{uuid.uuid4().hex}"
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, summary, severity_hint, primary_actor, entities, event_sequence
                )
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (
                    incident_id,
                    "Repository Test Incident",
                    "Repository test summary",
                    "high",
                    '{"actor_key":"demo-actor"}',
                    '{"primary_source_ip_address":"203.0.113.10"}',
                    '["ConsoleLogin","CreateAccessKey"]',
                ),
            )
        conn.commit()
    yield incident_id
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            for table in (
                "decision_review_events",
                "operator_decisions",
                "decision_support_results",
                "coverage_assessments",
                "detector_results",
                "evidence_packages",
                "incident_events",
                "incidents",
            ):
                cur.execute(f"DELETE FROM {table} WHERE incident_id = %s", (incident_id,))
        conn.commit()


@pytest.fixture
def policy_version(repository_test_dsn: str):
    version = f"test-policy-{uuid.uuid4().hex}"
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO policy_snapshots (policy_version, policy_json)
                VALUES (%s, %s::jsonb)
                """,
                (version, '{"allowed_actions":["collect_more_evidence"]}'),
            )
        conn.commit()
    yield version
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM decision_support_results WHERE policy_version = %s", (version,))
            cur.execute("DELETE FROM policy_snapshots WHERE policy_version = %s", (version,))
        conn.commit()
