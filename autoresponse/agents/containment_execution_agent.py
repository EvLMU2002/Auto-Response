import json
import re

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from tools.firewall_tool import execute_containment


def _parse_decision(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    # Accept model outputs that come back as fenced JSON blocks.
    fenced_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL | re.IGNORECASE)
    if fenced_match:
        text = fenced_match.group(1).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None

    return parsed if isinstance(parsed, dict) else None


def deterministic_execution_callback(callback_context: CallbackContext):
    decision = _parse_decision(callback_context.state.get("containment_decision"))
    if not isinstance(decision, dict):
        result = {
            "error": "missing_containment_decision",
            "message": "containment_decision was not found or could not be parsed as a JSON object",
            "pipeline_mode": "deterministic",
        }
        callback_context.state["execution_result"] = result
        return Content(parts=[Part(text=json.dumps(result))])

    action = decision.get("action")
    target = decision.get("target")
    reason = decision.get("reason") or "No reason provided"
    if not action or not target:
        result = {
            "error": "invalid_containment_decision",
            "message": "containment_decision is missing action or target",
            "pipeline_mode": "deterministic",
        }
        callback_context.state["execution_result"] = result
        return Content(parts=[Part(text=json.dumps(result))])

    result = execute_containment(str(action), str(target), str(reason))
    callback_context.state["execution_result"] = result
    return Content(parts=[Part(text=json.dumps(result))])


containment_execution_agent = SequentialAgent(
    name="ContainmentExecutionAgent",
    description="Deterministic containment execution agent.",
    before_agent_callback=deterministic_execution_callback,
    sub_agents=[],
)