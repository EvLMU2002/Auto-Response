import json

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from agents.data.historical_logs import HISTORICAL_LOGS


def _safe_json_loads(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def deterministic_correlation_callback(callback_context: CallbackContext):
    payload = callback_context.state.get("generated_log")
    alert = _safe_json_loads(payload)
    if not isinstance(alert, dict):
        result = {
            "error": "missing_generated_log",
            "message": "generated_log was not found or was invalid",
            "required_keys": ["generated_log"],
        }
        callback_context.state["correlation_result"] = result
        return Content(parts=[Part(text=json.dumps(result))])

    source_ip = alert.get("source_ip")
    if not source_ip:
        result = {
            "error": "missing_source_ip",
            "message": "source_ip is missing from generated_log",
            "required_keys": ["generated_log.source_ip"],
        }
        callback_context.state["correlation_result"] = result
        return Content(parts=[Part(text=json.dumps(result))])

    matches = [entry for entry in HISTORICAL_LOGS if entry.get("ip") == source_ip]
    if not matches:
        result = {
            "previously_seen": False,
            "times_seen": 0,
            "known_attack_types": [],
            "last_seen_days_ago": None,
            "pattern_detected": "no historical match",
            "confidence_boost": "LOW",
        }
    else:
        known_attack_types = sorted(
            {str(entry.get("event")) for entry in matches if entry.get("event")}
        )
        min_days = min(
            [int(entry.get("days_ago", 0)) for entry in matches if entry.get("days_ago") is not None],
            default=None,
        )
        result = {
            "previously_seen": True,
            "times_seen": len(matches),
            "known_attack_types": known_attack_types,
            "last_seen_days_ago": min_days,
            "pattern_detected": "repeat offender" if len(matches) > 1 else "single prior observation",
            "confidence_boost": "HIGH" if len(matches) > 1 else "MEDIUM",
        }

    callback_context.state["correlation_result"] = result
    return Content(parts=[Part(text=json.dumps(result))])


correlation_agent = SequentialAgent(
    name="CorrelationAgent",
    description="Deterministic correlation agent based on historical source_ip matches.",
    before_agent_callback=deterministic_correlation_callback,
    sub_agents=[],
)
