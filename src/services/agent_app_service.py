from __future__ import annotations

from dataclasses import dataclass
import os

from src.agent.auth import load_codex_access_token, should_use_codex_auth, validate_codex_auth_base_url
from src.agent.openai_compat import OpenAICompatConfig
from src.agent.service import DecisionSupportAgent
from src.db.connection import create_connection, load_postgres_config
from src.repositories.service_bundles import AgentRepositoryBundle, DecisionSupportRepositoryBundle
from src.services.decision_support_app_service import DecisionSupportAppService


@dataclass
class AgentAppConfig:
    model: str
    base_url: str
    api_key: str | None = None
    chat_path: str = "/chat/completions"
    temperature: float = 0.2
    max_tokens: int | None = None
    max_reasoning_steps: int = 6


def load_agent_app_config(env: dict[str, str] | None = None) -> AgentAppConfig:
    env = env or os.environ
    model = _first_present(env, "OPENAI_MODEL", "LLM_MODEL", "AGENT_MODEL")
    base_url = _first_present(env, "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_COMPAT_BASE_URL")
    if not model:
        raise ValueError("Missing agent model. Set OPENAI_MODEL, LLM_MODEL, or AGENT_MODEL.")
    if not base_url:
        raise ValueError("Missing endpoint base URL. Set OPENAI_BASE_URL, OPENAI_API_BASE, or OPENAI_COMPAT_BASE_URL.")
    api_key = _first_present(env, "OPENAI_API_KEY", "AGENT_API_KEY")
    if api_key is None and should_use_codex_auth(env):
        validate_codex_auth_base_url(base_url)
        api_key = load_codex_access_token(env)
    return AgentAppConfig(
        model=model,
        base_url=base_url,
        api_key=api_key,
        chat_path=env.get("OPENAI_CHAT_PATH", "/chat/completions"),
        temperature=float(env.get("AGENT_TEMPERATURE", "0.2")),
        max_tokens=int(env["AGENT_MAX_TOKENS"]) if env.get("AGENT_MAX_TOKENS") else None,
        max_reasoning_steps=int(env.get("AGENT_MAX_REASONING_STEPS", "6")),
    )


def build_postgres_backed_agent(config: AgentAppConfig, env: dict[str, str] | None = None) -> DecisionSupportAgent:
    pg_config = load_postgres_config(env)

    def connection_factory():
        return create_connection(pg_config)

    repositories = AgentRepositoryBundle.from_connection_factory(connection_factory)
    decision_support_repositories = DecisionSupportRepositoryBundle.from_connection_factory(connection_factory)
    decision_support_service = DecisionSupportAppService(decision_support_repositories)
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
    agent = build_postgres_backed_agent(resolved_config, env=env)
    return agent.respond(
        incident_id=incident_id,
        user_query=user_query,
        policy_version=policy_version,
        request_fn=request_fn,
    )


def _first_present(env: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = env.get(key)
        if value:
            return value
    return None
