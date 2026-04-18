from __future__ import annotations

from src.repositories.incidents_repo import IncidentsRepository


def test_fetch_incident_returns_seeded_incident(repository_connection_factory, seeded_incident):
    repo = IncidentsRepository(repository_connection_factory)
    incident = repo.fetch_incident(seeded_incident)

    assert incident is not None
    assert incident["incident_id"] == seeded_incident
    assert incident["title"] == "Repository Test Incident"


def test_fetch_incident_returns_none_for_missing_id(repository_connection_factory):
    repo = IncidentsRepository(repository_connection_factory)
    assert repo.fetch_incident("missing-incident") is None
