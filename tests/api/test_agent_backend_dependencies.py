from __future__ import annotations

from agent_backend.dependencies import as_http_exception, get_agent_env


def test_get_agent_env_backfills_postgres_dsn(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://demo@db/sentinel")
    monkeypatch.delenv("POSTGRES_DSN", raising=False)

    env = get_agent_env()

    assert env["DATABASE_URL"] == "postgresql://demo@db/sentinel"
    assert env["POSTGRES_DSN"] == "postgresql://demo@db/sentinel"


def test_as_http_exception_maps_not_found_to_404():
    not_found = as_http_exception(ValueError("Incident not found: incident-1"))
    bad_request = as_http_exception(ValueError("Policy version is invalid"))

    assert not_found.status_code == 404
    assert bad_request.status_code == 400

