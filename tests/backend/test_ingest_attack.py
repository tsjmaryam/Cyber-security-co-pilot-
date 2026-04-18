from __future__ import annotations

import json
from pathlib import Path

import backend.ingest_attack as ingest_attack


class FakeCursor:
    def __init__(self, state):
        self.state = state
        self._last_row = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        sql = " ".join(str(query).split())
        params = params or ()

        if "DELETE FROM knowledge_entries" in sql:
            self.state["entries"] = {
                key: value
                for key, value in self.state["entries"].items()
                if not (value["source"] == "mitre_attack" and value["external_ref"] is None)
            }
            return

        if "INSERT INTO knowledge_domains" in sql:
            name, description = params
            if name not in self.state["domains"]:
                self.state["domain_ids"] += 1
                self.state["domains"][name] = {"id": self.state["domain_ids"], "name": name, "description": description}
            else:
                self.state["domains"][name]["description"] = description
            return

        if "SELECT id FROM knowledge_domains WHERE name =" in sql:
            name = params[0]
            domain = self.state["domains"].get(name)
            self._last_row = {"id": domain["id"]} if domain else None
            return

        if "INSERT INTO knowledge_entries" in sql:
            domain_id, title, content, external_ref = params
            self.state["entries"][("mitre_attack", external_ref)] = {
                "domain_id": domain_id,
                "title": title,
                "content": content,
                "entry_type": "threat",
                "source": "mitre_attack",
                "external_ref": external_ref,
                "confidence": 0.95,
            }
            return

        if "CREATE TABLE IF NOT EXISTS knowledge_domains" in sql or "ALTER TABLE knowledge_entries" in sql or "CREATE UNIQUE INDEX IF NOT EXISTS" in sql or "DROP INDEX IF EXISTS" in sql:
            return

        raise AssertionError(f"Unhandled SQL in fake ingest test: {sql}")

    def fetchone(self):
        return self._last_row


class FakeConnection:
    def __init__(self, state):
        self.state = state
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return FakeCursor(self.state)

    def commit(self):
        self.commits += 1


def test_ingest_attack_is_idempotent(monkeypatch, tmp_path: Path):
    bundle = {
        "objects": [
            {
                "type": "x-mitre-tactic",
                "name": "Credential Access",
                "description": "Steal credentials",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Brute Force",
                "description": "Guess passwords",
                "kill_chain_phases": [{"phase_name": "Credential Access"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
            },
        ]
    }
    data_path = tmp_path / "enterprise.json"
    data_path.write_text(json.dumps(bundle), encoding="utf-8")
    schema_path = tmp_path / "schema.sql"
    schema_path.write_text((Path(ingest_attack.__file__).resolve().parent / "schema.sql").read_text(encoding="utf-8"), encoding="utf-8")

    state = {"domains": {}, "entries": {}, "domain_ids": 0}
    fake_connection = FakeConnection(state)

    monkeypatch.setattr(ingest_attack, "DATA_PATH", data_path)
    monkeypatch.setattr(ingest_attack, "SCHEMA_PATH", schema_path)
    monkeypatch.setattr(ingest_attack, "load_postgres_config", lambda env: object())
    monkeypatch.setattr(ingest_attack, "create_connection", lambda config: fake_connection)

    ingest_attack.main()
    ingest_attack.main()

    assert len(state["domains"]) == 1
    assert len(state["entries"]) == 1
    assert ("mitre_attack", "T1110") in state["entries"]
    assert fake_connection.commits == 2
