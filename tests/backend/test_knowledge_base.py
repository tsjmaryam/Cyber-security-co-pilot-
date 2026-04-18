from __future__ import annotations

from backend.knowledge_base import KnowledgeBaseRepository, normalize_query


class FailIfCalledConnection:
    def __call__(self):
        raise AssertionError("Connection factory should not be called for empty normalized queries.")


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params):
        self.executed = (sql, params)

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, rows):
        self.cursor_obj = FakeCursor(rows)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return self.cursor_obj


def test_normalize_query_removes_ips_ports_and_timestamps():
    query = "203.0.113.4:443 brute force login 2025-01-15T14:00:00Z from host"
    assert normalize_query(query) == "brute & force & login & from & host"


def test_search_returns_empty_without_db_call_when_query_normalizes_to_empty():
    repo = KnowledgeBaseRepository(connection_factory=FailIfCalledConnection())
    assert repo.search("10.0.0.1:443 2025-01-15T14:00:00Z aaa", limit=5) == []


def test_search_executes_ranked_query_and_returns_rows():
    fake_connection = FakeConnection(
        rows=[{"title": "Brute Force", "score": 0.8}, {"title": "Password Spraying", "score": 0.6}]
    )
    repo = KnowledgeBaseRepository(connection_factory=lambda: fake_connection)

    results = repo.search("brute force login", limit=2)

    assert [row["title"] for row in results] == ["Brute Force", "Password Spraying"]
    assert fake_connection.cursor_obj.executed is not None
    _, params = fake_connection.cursor_obj.executed
    assert params == ("brute & force & login", "brute & force & login", 2)
