from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

import backend.dependencies as backend_dependencies
from agent_backend.main import app as agent_app
from backend.main import app as backend_app
from scripts import seed_demo_db


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_INCIDENT_ID = "incident_000000001"
APP_SCHEMA_PATH = PROJECT_ROOT / "src" / "db" / "schema.sql"


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


@pytest.mark.skipif(TestClient is None, reason="fastapi test client unavailable")
def test_live_backend_and_agent_routes_against_seeded_demo_db(monkeypatch):
    dsn = _resolve_dsn()
    if not dsn:
        pytest.skip("No POSTGRES_DSN or DATABASE_URL available for live integration test.")

    monkeypatch.setenv("POSTGRES_DSN", dsn)
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("AGENT_AUTH_MODE", "mock")
    monkeypatch.setenv("AGENT_USE_MCP_CYBER_CONTEXT", "0")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_API_KEY", raising=False)

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(APP_SCHEMA_PATH.read_text(encoding="utf-8"))
            cur.execute("DELETE FROM decision_support_results WHERE policy_version LIKE 'test-policy-%'")
            cur.execute("DELETE FROM policy_snapshots WHERE policy_version LIKE 'test-policy-%'")
            cur.execute("DELETE FROM policy_snapshots WHERE policy_version = 'zzz-latest-policy'")
        conn.commit()

    seed_demo_db.main()
    backend_dependencies.get_connection_factory.cache_clear()

    backend_client = TestClient(backend_app)
    agent_client = TestClient(agent_app)

    incident_response = backend_client.get(f"/incidents/{DEMO_INCIDENT_ID}")
    assert incident_response.status_code == 200
    incident_payload = incident_response.json()
    assert incident_payload["incident"]["incident_id"] == DEMO_INCIDENT_ID

    decision_response = backend_client.get(f"/incidents/{DEMO_INCIDENT_ID}/decision-support")
    assert decision_response.status_code == 200
    assert decision_response.json()["result"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"

    coverage_response = backend_client.get(f"/incidents/{DEMO_INCIDENT_ID}/coverage-review")
    assert coverage_response.status_code == 200
    coverage_payload = coverage_response.json()["review"]
    assert coverage_payload["recommendation_may_be_incomplete"] is True

    agent_auth_response = agent_client.get(f"/incidents/{DEMO_INCIDENT_ID}/agent-auth")
    assert agent_auth_response.status_code == 200
    assert agent_auth_response.json()["result"]["auth_mode"] == "mock"

    agent_query_response = agent_client.post(
        f"/incidents/{DEMO_INCIDENT_ID}/agent-query",
        json={"user_query": "What should I do next?"},
    )
    assert agent_query_response.status_code == 200
    result = agent_query_response.json()["result"]
    assert result["incident_id"] == DEMO_INCIDENT_ID
    assert result["raw_response"]["mock_mode"] is True
    assert "Reset credentials" in result["answer"]
    assert result["context_summary"]["has_incident"] is True
