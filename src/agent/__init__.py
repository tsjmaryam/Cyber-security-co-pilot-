"""Agent module for Postgres-backed context retrieval and OpenAI-compatible reasoning."""

from .auth import CodexAuthError
from .openai_compat import OpenAICompatConfig, OpenAICompatError
from .service import DecisionSupportAgent

__all__ = [
    "CodexAuthError",
    "DecisionSupportAgent",
    "OpenAICompatConfig",
    "OpenAICompatError",
]
