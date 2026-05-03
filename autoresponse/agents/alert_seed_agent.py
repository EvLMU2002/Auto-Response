import json

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from agents.log_generator import generate_mock_alert


def _safe_json_loads(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def _serialize_alert(alert: dict) -> dict:
    """Convert datetime objects to strings for session state storage."""
    serialized = alert.copy()
    serialized["logs"] = [
        {**log, "timestamp": log["timestamp"].isoformat()} for log in alert.get("logs", [])
    ]
    return serialized


def alert_seed_callback(callback_context: CallbackContext):
    existing = _safe_json_loads(callback_context.state.get("generated_log"))
    if isinstance(existing, dict) and existing.get("source_ip"):
        result = {
            "status": "existing_alert_reused",
            "source_ip": existing.get("source_ip", "unknown"),
            "target_host": existing.get("target_host", "unknown-host"),
            "log_count": existing.get("log_count", 0),
        }
        return Content(parts=[Part(text=json.dumps(result))])

    alert = _serialize_alert(generate_mock_alert())
    callback_context.state["generated_log"] = json.dumps(alert)

    result = {
        "status": "new_alert_generated",
        "source_ip": alert.get("source_ip", "unknown"),
        "target_host": alert.get("target_host", "unknown-host"),
        "log_count": alert.get("log_count", 0),
    }
    return Content(parts=[Part(text=json.dumps(result))])


alert_seed_agent = SequentialAgent(
    name="AlertSeedAgent",
    description="Ensures generated_log exists in session state before analysis.",
    before_agent_callback=alert_seed_callback,
    sub_agents=[],
)
