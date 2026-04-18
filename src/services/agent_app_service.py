from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Literal

from src.logging_utils import get_logger
from src.agent.auth import (
    CodexAuthError,
    load_codex_access_token,
    should_use_codex_auth,
    validate_codex_auth_base_url,
)
from src.agent.mcp_client import McpCyberContextClient
from src.agent.mock_agent import generate_mock_agent_response
from src.agent.openai_compat import OpenAICompatConfig
from src.agent.service import DecisionSupportAgent
from src.db.connection import create_connection, load_postgres_config
from src.repositories.service_bundles import AgentRepositoryBundle, DecisionSupportRepositoryBundle
from src.services.decision_support_app_service import DecisionSupportAppService

logger = get_logger(__name__)


AgentAuthMode = Literal["api_key", "openai_session", "mock"]
DEFAULT_AGENT_MODEL = "gpt-5.4"


@dataclass
class AgentAppConfig:
    model: str
    base_url: str
    auth_mode: AgentAuthMode
    api_key: str | None = None
    chat_path: str = "/chat/completions"
    temperature: float = 0.2
    max_tokens: int | None = None
    max_reasoning_steps: int = 6


def load_agent_app_config(env: dict[str, str] | None = None) -> AgentAppConfig:
    env = os.environ if env is None else env
    model = _first_present(env, "OPENAI_MODEL", "LLM_MODEL", "AGENT_MODEL") or DEFAULT_AGENT_MODEL
    auth_mode = resolve_agent_auth_mode(env)
    base_url = _first_present(env, "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_COMPAT_BASE_URL")
    if auth_mode == "mock":
        base_url = base_url or "mock://local/v1"
    if not base_url:
        raise ValueError("Missing endpoint base URL. Set OPENAI_BASE_URL, OPENAI_API_BASE, or OPENAI_COMPAT_BASE_URL.")
    api_key = resolve_agent_api_key(base_url=base_url, auth_mode=auth_mode, env=env)
    return AgentAppConfig(
        model=model,
        base_url=base_url,
        auth_mode=auth_mode,
        api_key=api_key,
        chat_path=env.get("OPENAI_CHAT_PATH", "/chat/completions"),
        temperature=float(env.get("AGENT_TEMPERATURE", "0.2")),
        max_tokens=int(env["AGENT_MAX_TOKENS"]) if env.get("AGENT_MAX_TOKENS") else None,
        max_reasoning_steps=int(env.get("AGENT_MAX_REASONING_STEPS", "6")),
    )


def build_postgres_backed_agent(config: AgentAppConfig, env: dict[str, str] | None = None) -> DecisionSupportAgent:
    logger.info(
        "Building Postgres-backed agent model=%s base_url=%s auth_mode=%s",
        config.model,
        config.base_url,
        config.auth_mode,
    )
    pg_config = load_postgres_config(env)

    def connection_factory():
        return create_connection(pg_config)

    repositories = AgentRepositoryBundle.from_connection_factory(connection_factory)
    decision_support_repositories = DecisionSupportRepositoryBundle.from_connection_factory(connection_factory)
    decision_support_service = DecisionSupportAppService(decision_support_repositories)
    mcp_client = McpCyberContextClient.from_env(env)
    endpoint_config = OpenAICompatConfig(
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        chat_path=config.chat_path,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )
    return DecisionSupportAgent(
        repositories=repositories,
        decision_support_service=decision_support_service,
        mcp_client=mcp_client,
        endpoint_config=endpoint_config,
        max_reasoning_steps=config.max_reasoning_steps,
    )


def query_incident_agent(
    incident_id: str,
    user_query: str,
    config: AgentAppConfig | None = None,
    env: dict[str, str] | None = None,
    policy_version: str | None = None,
    request_fn=None,
) -> dict:
    resolved_config = config or load_agent_app_config(env)
    logger.info(
        "Querying incident agent incident_id=%s model=%s auth_mode=%s",
        incident_id,
        resolved_config.model,
        resolved_config.auth_mode,
    )
    agent = build_postgres_backed_agent(resolved_config, env=env)
    if resolved_config.auth_mode == "mock":
        return generate_mock_agent_response(
            repositories=agent.repositories,
            decision_support_service=agent.decision_support_service,
            incident_id=incident_id,
            user_query=user_query,
            policy_version=policy_version,
            model=resolved_config.model,
            endpoint=resolved_config.base_url.rstrip("/") + resolved_config.chat_path,
        )
    return agent.respond(
        incident_id=incident_id,
        user_query=user_query,
        policy_version=policy_version,
        request_fn=request_fn,
    )


def resolve_agent_auth_mode(env: dict[str, str] | None = None) -> AgentAuthMode:
    env = os.environ if env is None else env
    configured = env.get("AGENT_AUTH_MODE")
    if configured:
        normalized = configured.strip().lower()
        if normalized == "api_key":
            return "api_key"
        if normalized == "openai_session":
            return "openai_session"
        if normalized == "mock":
            return "mock"
        raise ValueError("Invalid AGENT_AUTH_MODE. Use `api_key`, `openai_session`, or `mock`.")
    if should_use_codex_auth(env):
        return "openai_session"
    return "api_key"


def resolve_agent_api_key(base_url: str, auth_mode: AgentAuthMode, env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    if auth_mode == "mock":
        return "mock-token"
    if auth_mode == "api_key":
        api_key = _first_present(env, "OPENAI_API_KEY", "AGENT_API_KEY")
        if not api_key:
            raise ValueError(
                "Missing agent API key for production mode. "
                "Set OPENAI_API_KEY or AGENT_API_KEY, or explicitly switch to AGENT_AUTH_MODE=openai_session for local development."
            )
        return api_key
    validate_codex_auth_base_url(base_url)
    try:
        api_key = load_codex_access_token(env)
    except CodexAuthError as exc:
        raise ValueError(
            "OpenAI session mode is only for local development and requires a valid Codex auth session in ~/.codex/auth.json."
        ) from exc
    logger.warning("Using OpenAI session auth mode for local development only")
    return api_key


def describe_agent_auth(env: dict[str, str] | None = None) -> dict[str, object]:
    env = os.environ if env is None else env
    auth_mode = resolve_agent_auth_mode(env)
    base_url = _first_present(env, "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_COMPAT_BASE_URL")
    if auth_mode == "mock":
        base_url = base_url or "mock://local/v1"
    model = _first_present(env, "OPENAI_MODEL", "LLM_MODEL", "AGENT_MODEL") or DEFAULT_AGENT_MODEL
    using_openai_session = auth_mode == "openai_session"
    using_mock_mode = auth_mode == "mock"
    session_allowed = (base_url or "").rstrip("/").lower() == "https://api.openai.com/v1"
    has_api_key = bool(_first_present(env, "OPENAI_API_KEY", "AGENT_API_KEY"))
    return {
        "auth_mode": auth_mode,
        "base_url": base_url,
        "model": model,
        "is_production_ready": auth_mode == "api_key" and has_api_key,
        "non_production_mode": using_openai_session or using_mock_mode,
        "session_mode_allowed": session_allowed if using_openai_session else None,
        "mock_mode": using_mock_mode,
        "labels": {
            "api_key": "Production mode",
            "openai_session": "Local/dev only",
            "mock": "Mock mode",
        },
    }


def _first_present(env: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = env.get(key)
        if value:
            return value
    return None
