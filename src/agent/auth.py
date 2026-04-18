from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class CodexAuthError(RuntimeError):
    """Raised when Codex auth cannot be loaded safely."""


def load_codex_access_token(env: dict[str, str] | None = None) -> str:
    env = env or os.environ
    auth_path = _resolve_auth_path(env)
    try:
        payload = json.loads(auth_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CodexAuthError(f"Codex auth file not found: {auth_path}") from exc
    except json.JSONDecodeError as exc:
        raise CodexAuthError(f"Codex auth file is not valid JSON: {auth_path}") from exc

    tokens = payload.get("tokens")
    if not isinstance(tokens, dict):
        raise CodexAuthError("Codex auth file is missing tokens.")
    access_token = tokens.get("access_token")
    if not access_token or not isinstance(access_token, str):
        raise CodexAuthError("Codex auth file does not contain an access token.")
    return access_token


def should_use_codex_auth(env: dict[str, str] | None = None) -> bool:
    env = env or os.environ
    return _is_truthy(env.get("AGENT_USE_CODEX_AUTH")) or _is_truthy(env.get("USE_CODEX_AUTH"))


def validate_codex_auth_base_url(base_url: str) -> None:
    normalized = base_url.rstrip("/").lower()
    if normalized != "https://api.openai.com/v1":
        raise CodexAuthError(
            "Codex auth fallback is only supported for https://api.openai.com/v1. "
            "Set OPENAI_BASE_URL accordingly or provide a normal API key for other endpoints."
        )


def _resolve_auth_path(env: dict[str, str]) -> Path:
    override = env.get("CODEX_AUTH_PATH")
    if override:
        return Path(override).expanduser().resolve()
    return Path(env.get("HOME") or Path.home()) / ".codex" / "auth.json"


def _is_truthy(value: Any) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
