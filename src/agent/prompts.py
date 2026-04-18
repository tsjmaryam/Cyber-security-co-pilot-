from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """You are a security triage assistant.
You are grounded only in the provided structured incident context, evidence package, detector outputs, coverage state, and decision-support result.
Do not invent evidence, checks, actions, or policy.
When coverage is incomplete, say so clearly.
If a recommendation exists, explain it faithfully rather than replacing it.
Prefer concise operator-facing language unless the user explicitly asks for technical detail."""


def build_messages(user_query: str, context_bundle: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Answer the operator request using the provided context.\n\n"
                f"Operator request:\n{user_query}\n\n"
                "Structured context:\n"
                f"{json.dumps(context_bundle, indent=2, default=str)}"
            ),
        },
    ]
