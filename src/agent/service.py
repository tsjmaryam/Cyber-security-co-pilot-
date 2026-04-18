from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .openai_compat import OpenAICompatConfig, create_chat_completion, extract_text_content
from .react import build_correction_message, build_observation_message, build_react_messages, parse_react_step
from .tools import AgentRuntimeState
from .context import AgentRepositoryBundle


class DecisionSupportGenerator(Protocol):
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]: ...


@dataclass
class DecisionSupportAgent:
    repositories: AgentRepositoryBundle
    decision_support_service: DecisionSupportGenerator
    endpoint_config: OpenAICompatConfig
    max_reasoning_steps: int = 6

    def respond(
        self,
        incident_id: str,
        user_query: str,
        policy_version: str | None = None,
        request_fn=None,
    ) -> dict[str, Any]:
        runtime = AgentRuntimeState(
            repositories=self.repositories,
            decision_support_service=self.decision_support_service,
            incident_id=incident_id,
            policy_version=policy_version,
        )
        tools = runtime.build_tools()
        messages = build_react_messages(
            user_query=user_query,
            incident_id=incident_id,
            tool_specs=[{"name": tool.name, "description": tool.description} for tool in tools.values()],
        )
        reasoning_trace: list[dict[str, Any]] = []
        answer: str | None = None
        last_response: dict[str, Any] | None = None

        for step_index in range(1, self.max_reasoning_steps + 1):
            response = create_chat_completion(
                self.endpoint_config,
                messages,
                request_fn=request_fn,
            )
            last_response = response
            content = extract_text_content(response)
            react_step = parse_react_step(content)
            trace_item = {
                "step": step_index,
                "thought": react_step.thought,
                "action": react_step.action,
            }
            reasoning_trace.append(trace_item)

            if react_step.action == "finish":
                if not any(runtime.context_summary().values()):
                    messages.append({"role": "assistant", "content": react_step.raw_content})
                    messages.append({"role": "user", "content": build_correction_message("You must use at least one tool before finishing.")})
                    trace_item["status"] = "rejected"
                    continue
                answer = react_step.final_answer or react_step.raw_content.strip()
                trace_item["status"] = "finished"
                break

            tool = tools.get(react_step.action)
            if tool is None:
                messages.append({"role": "assistant", "content": react_step.raw_content})
                messages.append({"role": "user", "content": build_correction_message(f"Unknown tool `{react_step.action}`.")})
                trace_item["status"] = "unknown_tool"
                continue

            try:
                observation = tool.handler(react_step.action_input)
            except Exception as exc:
                observation = {"error": str(exc)}
                trace_item["status"] = "tool_error"
            else:
                trace_item["status"] = "observed"
            trace_item["observation"] = observation
            messages.append({"role": "assistant", "content": react_step.raw_content})
            messages.append({"role": "user", "content": build_observation_message(tool.name, observation)})

        if answer is None:
            raise RuntimeError(f"Agent did not finish within {self.max_reasoning_steps} reasoning steps.")

        return {
            "incident_id": incident_id,
            "user_query": user_query,
            "answer": answer,
            "model": self.endpoint_config.model,
            "endpoint": self.endpoint_config.endpoint(),
            "decision_support_source": runtime.decision_support_source,
            "context_summary": runtime.context_summary(),
            "reasoning_trace": reasoning_trace,
            "raw_response": last_response,
        }
