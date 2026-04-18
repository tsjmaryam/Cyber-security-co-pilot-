from __future__ import annotations

import json
import sys
from pathlib import Path

from pgembed import get_server

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.logging_utils import configure_logging, get_logger


logger = get_logger(__name__)


def main() -> int:
    configure_logging()
    repo_root = REPO_ROOT
    pgdata = repo_root / ".local" / "pgembed" / "data"
    state_path = repo_root / ".local" / "services" / "embedded_postgres.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    pgdata.parent.mkdir(parents=True, exist_ok=True)

    server = get_server(pgdata, cleanup_mode=None)
    databases = set(server.psql("SELECT datname FROM pg_database;").split())
    db_name = "cyber_copilot"
    if db_name not in databases:
        logger.info("Creating database db_name=%s", db_name)
        server.psql(f'CREATE DATABASE "{db_name}";')

    state = {
        "pgdata": str(pgdata),
        "pid": server.get_pid(),
        "postgres_uri": server.get_uri("postgres"),
        "database_uri": server.get_uri(db_name),
    }
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
