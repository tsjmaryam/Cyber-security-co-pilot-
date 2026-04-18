from __future__ import annotations

import pytest

from src.services.agent_app_service import describe_agent_auth, resolve_agent_api_key, resolve_agent_auth_mode


def test_agent_auth_mode_defaults_to_api_key():
    assert resolve_agent_auth_mode({}) == "api_key"


def test_default_model_is_gpt_5_4():
    result = describe_agent_auth(
        {
            "AGENT_AUTH_MODE": "api_key",
            "OPENAI_BASE_URL": "https://api.openai.com/v1",
            "OPENAI_API_KEY": "test-key",
        }
    )
    assert result["model"] == "gpt-5.4"


def test_agent_auth_mode_uses_explicit_openai_session():
    assert resolve_agent_auth_mode({"AGENT_AUTH_MODE": "openai_session"}) == "openai_session"


def test_agent_auth_mode_supports_mock():
    assert resolve_agent_auth_mode({"AGENT_AUTH_MODE": "mock"}) == "mock"


def test_api_key_mode_requires_key():
    with pytest.raises(ValueError, match="Missing agent API key"):
        resolve_agent_api_key(
            base_url="https://api.openai.com/v1",
            auth_mode="api_key",
            env={},
        )


def test_session_mode_requires_openai_base_url():
    with pytest.raises(Exception):
        resolve_agent_api_key(
            base_url="http://localhost:11434/v1",
            auth_mode="openai_session",
            env={"CODEX_AUTH_PATH": "C:/missing/auth.json"},
        )


def test_describe_agent_auth_reports_non_production_mode():
    result = describe_agent_auth(
        {
            "AGENT_AUTH_MODE": "openai_session",
            "OPENAI_BASE_URL": "https://api.openai.com/v1",
            "OPENAI_MODEL": "gpt-5.4",
        }
    )
    assert result["auth_mode"] == "openai_session"
    assert result["non_production_mode"] is True
    assert result["session_mode_allowed"] is True


def test_describe_agent_auth_reports_mock_mode():
    result = describe_agent_auth({"AGENT_AUTH_MODE": "mock"})
    assert result["auth_mode"] == "mock"
    assert result["mock_mode"] is True
    assert result["model"] == "gpt-5.4"
