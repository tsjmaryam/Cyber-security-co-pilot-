from __future__ import annotations

import sys
import types

from src.db.connection import PostgresConfig, create_connection, load_postgres_config, schema_path


def test_load_postgres_config_and_connection_kwargs():
    config = load_postgres_config(
        {
            "POSTGRES_HOST": "db.example",
            "POSTGRES_PORT": "6543",
            "POSTGRES_DB": "sentinel",
            "POSTGRES_USER": "demo",
            "POSTGRES_PASSWORD": "secret",
            "POSTGRES_SSLMODE": "require",
        }
    )

    assert config.port == 6543
    assert config.as_connection_kwargs() == {
        "host": "db.example",
        "port": 6543,
        "dbname": "sentinel",
        "user": "demo",
        "password": "secret",
        "sslmode": "require",
    }


def test_create_connection_uses_dsn_or_keyword_args(monkeypatch):
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_connect(*args, **kwargs):
        calls.append((args, kwargs))
        return {"args": args, "kwargs": kwargs}

    psycopg_module = types.ModuleType("psycopg")
    psycopg_module.connect = fake_connect
    rows_module = types.ModuleType("psycopg.rows")
    rows_module.dict_row = object()

    monkeypatch.setitem(sys.modules, "psycopg", psycopg_module)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows_module)

    dsn_result = create_connection(PostgresConfig(dsn="postgresql://demo@db/sentinel"))
    kwargs_result = create_connection(PostgresConfig(host="db", dbname="sentinel", user="demo"))

    assert dsn_result["args"] == ("postgresql://demo@db/sentinel",)
    assert dsn_result["kwargs"] == {"row_factory": rows_module.dict_row}
    assert kwargs_result["args"] == ()
    assert kwargs_result["kwargs"]["host"] == "db"
    assert kwargs_result["kwargs"]["dbname"] == "sentinel"
    assert kwargs_result["kwargs"]["user"] == "demo"
    assert kwargs_result["kwargs"]["row_factory"] is rows_module.dict_row
    assert len(calls) == 2


def test_schema_path_points_to_repo_schema():
    assert schema_path().parts[-3:] == ("src", "db", "schema.sql")
