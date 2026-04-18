from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class OpenAICompatConfig:
    model: str
    base_url: str
    api_key: str | None = None
    chat_path: str = "/chat/completions"
    temperature: float = 0.2
    max_tokens: int | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def endpoint(self) -> str:
        return self.base_url.rstrip("/") + self.chat_path


class OpenAICompatError(RuntimeError):
    """Raised when an OpenAI-compatible endpoint returns an invalid or failing response."""


def create_chat_completion(
    config: OpenAICompatConfig,
    messages: list[dict[str, Any]],
    request_fn: Callable[[urllib.request.Request], Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": config.temperature,
    }
    if config.max_tokens is not None:
        payload["max_tokens"] = config.max_tokens

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", **config.extra_headers}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    request = urllib.request.Request(config.endpoint(), data=body, headers=headers, method="POST")
    transport = request_fn or urllib.request.urlopen

    try:
        with transport(request) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # pragma: no cover - network boundary
        detail = exc.read().decode("utf-8", errors="ignore")
        raise OpenAICompatError(f"Endpoint returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:  # pragma: no cover - network boundary
        raise OpenAICompatError(f"Endpoint connection failed: {exc.reason}") from exc

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OpenAICompatError("Endpoint returned invalid JSON.") from exc
    if "choices" not in parsed:
        raise OpenAICompatError("Endpoint response missing choices.")
    return parsed


def extract_text_content(response: dict[str, Any]) -> str:
    try:
        message = response["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpenAICompatError("Endpoint response missing choices[0].message.") from exc
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text", "")))
        return "\n".join(part for part in text_parts if part)
    return str(content)
