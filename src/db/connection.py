from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PostgresConfig:
    dsn: str | None = None
    host: str | None = None
    port: int | None = None
    dbname: str | None = None
    user: str | None = None
    password: str | None = None
    sslmode: str | None = None

    def as_connection_kwargs(self) -> dict[str, Any]:
        if self.dsn:
            return {"conninfo": self.dsn}
        kwargs = {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
            "sslmode": self.sslmode,
        }
        return {key: value for key, value in kwargs.items() if value is not None}


def load_postgres_config(env: dict[str, str] | None = None) -> PostgresConfig:
    env = env or os.environ
    return PostgresConfig(
        dsn=env.get("POSTGRES_DSN"),
        host=env.get("POSTGRES_HOST"),
        port=int(env["POSTGRES_PORT"]) if env.get("POSTGRES_PORT") else None,
        dbname=env.get("POSTGRES_DB"),
        user=env.get("POSTGRES_USER"),
        password=env.get("POSTGRES_PASSWORD"),
        sslmode=env.get("POSTGRES_SSLMODE"),
    )


def create_connection(config: PostgresConfig):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        raise RuntimeError("psycopg is required for Postgres-backed application services.") from exc
    kwargs = config.as_connection_kwargs()
    if "conninfo" in kwargs:
        return psycopg.connect(kwargs["conninfo"], row_factory=dict_row)
    return psycopg.connect(row_factory=dict_row, **kwargs)


def schema_path(project_root: str | Path = ".") -> Path:
    return Path(project_root).resolve() / "src" / "db" / "schema.sql"
