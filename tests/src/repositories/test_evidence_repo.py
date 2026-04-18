from __future__ import annotations

import psycopg

from src.repositories.evidence_repo import EvidenceRepository


def test_fetch_latest_evidence_package_returns_newest(repository_connection_factory, repository_test_dsn, seeded_incident):
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO evidence_packages (incident_id, summary_json, provenance_json, raw_refs_json)
                VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (seeded_incident, '{"summary":"older"}', '{"source":"test"}', '{"ref":"a"}'),
            )
            cur.execute(
                """
                INSERT INTO evidence_packages (incident_id, summary_json, provenance_json, raw_refs_json)
                VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (seeded_incident, '{"summary":"newer"}', '{"source":"test"}', '{"ref":"b"}'),
            )
        conn.commit()

    repo = EvidenceRepository(repository_connection_factory)
    result = repo.fetch_latest_evidence_package(seeded_incident)

    assert result is not None
    assert result["summary_json"]["summary"] == "newer"
