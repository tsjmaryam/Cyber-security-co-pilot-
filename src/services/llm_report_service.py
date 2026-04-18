from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from src.agent.openai_compat import OpenAICompatConfig, OpenAICompatError, create_chat_completion, extract_text_content
from src.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class LlmReportService:
    endpoint_config: OpenAICompatConfig

    def generate_report(self, context: dict[str, Any]) -> dict[str, Any]:
        logger.info("Generating LLM approval report incident_id=%s model=%s", context.get("incident_id"), self.endpoint_config.model)
        messages = [
            {
                "role": "system",
                "content": (
                    "You are Sentinel, a cybersecurity co-pilot writing a concise one-page incident approval report. "
                    "Use only the provided facts. Do not invent facts, actions, users, or evidence. "
                    "Return strict JSON with these keys only: "
                    "summary, approved_action_reason, operator_rationale, why_sentinel_is_concerned, blind_spots, what_could_change_the_decision. "
                    "The last three keys must be arrays of strings."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(context, indent=2),
            },
        ]
        response = create_chat_completion(self.endpoint_config, messages)
        content = extract_text_content(response)
        draft = _parse_json_payload(content)
        logger.info("LLM approval report generated incident_id=%s", context.get("incident_id"))
        return {
            "summary": _as_str(draft.get("summary"), context.get("summary", "")),
            "approved_action_reason": _as_str(draft.get("approved_action_reason"), _as_str(_as_record(context.get("approved_action")).get("reason"), "")),
            "operator_rationale": _as_str(draft.get("operator_rationale"), context.get("operator_rationale", "")),
            "why_sentinel_is_concerned": _normalize_string_list(draft.get("why_sentinel_is_concerned")),
            "blind_spots": _normalize_string_list(draft.get("blind_spots")),
            "what_could_change_the_decision": _normalize_string_list(draft.get("what_could_change_the_decision")),
        }

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "LlmReportService | None":
        api_key = env.get("OPENAI_API_KEY")
        base_url = env.get("OPENAI_BASE_URL")
        model = env.get("OPENAI_MODEL") or env.get("LLM_MODEL") or "gpt-5-mini"
        if not api_key or not base_url:
            return None
        return cls(
            endpoint_config=OpenAICompatConfig(
                model=model,
                base_url=base_url,
                api_key=api_key,
                chat_path=env.get("OPENAI_CHAT_PATH", "/chat/completions"),
                temperature=0.2,
                max_tokens=int(env["REPORT_MAX_TOKENS"]) if env.get("REPORT_MAX_TOKENS") else 700,
                extra_headers={"User-Agent": "sentinel-report/1.0"},
            )
        )


def _parse_json_payload(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 3:
            text = parts[1]
            if text.startswith("json"):
                text = text[4:]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise OpenAICompatError("LLM report response was not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise OpenAICompatError("LLM report response JSON must be an object.")
    return payload


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _as_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any, fallback: str = "") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback
