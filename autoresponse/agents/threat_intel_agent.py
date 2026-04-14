import json

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from tools.threat_intel_server import check_abuseipdb


def _error_payload(message: str) -> dict:
    return {
        "error": "missing_data",
        "message": message,
        "required_keys": ["generated_log"],
    }


async def threat_intel_callback(callback_context: CallbackContext):
    payload = callback_context.state.get("generated_log")
    if not payload:
        error = _error_payload("generated_log is missing from session state")
        callback_context.state["threat_intel_result"] = error
        return Content(parts=[Part(text=json.dumps(error))])

    try:
        alert = json.loads(payload)
    except json.JSONDecodeError:
        error = {
            "error": "invalid_generated_log",
            "message": "generated_log is not valid JSON",
            "required_keys": ["generated_log"],
        }
        callback_context.state["threat_intel_result"] = error
        return Content(parts=[Part(text=json.dumps(error))])

    source_ip = alert.get("source_ip")
    if not source_ip:
        error = {
            "error": "missing_source_ip",
            "message": "source_ip is missing from generated_log",
            "required_keys": ["generated_log.source_ip"],
        }
        callback_context.state["threat_intel_result"] = error
        return Content(parts=[Part(text=json.dumps(error))])

    result = await check_abuseipdb(str(source_ip))
    callback_context.state["threat_intel_result"] = result
    return Content(parts=[Part(text=json.dumps(result))])


threat_intel_agent = SequentialAgent(
    name="ThreatIntelAgent",
    description="Deterministic threat intel agent that queries threat_intel_server and returns raw JSON.",
    before_agent_callback=threat_intel_callback,
    sub_agents=[],
)