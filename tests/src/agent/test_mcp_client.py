from __future__ import annotations

from pathlib import Path

from src.agent.mcp_client import McpClientError, McpCyberContextClient


def test_mcp_client_falls_back_to_postgres_when_npm_is_unavailable(monkeypatch):
    client = McpCyberContextClient(project_root=Path("."), enabled=True, env={"POSTGRES_DSN": "postgresql://test"})

    monkeypatch.setattr(
        McpCyberContextClient,
        "_search_via_mcp",
        lambda self, query, limit: (_ for _ in ()).throw(McpClientError("npm missing")),
    )
    monkeypatch.setattr(
        McpCyberContextClient,
        "_search_via_postgres",
        lambda self, query, limit: [{"title": "Brute Force", "score": 0.9}],
    )

    results = client.search("brute force login", limit=3)

    assert results == [{"title": "Brute Force", "score": 0.9}]
