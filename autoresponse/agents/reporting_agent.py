import json

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from tools.reporting_tool import save_incident_report


def _safe_json_loads(value):
	if isinstance(value, dict):
		return value
	if isinstance(value, str):
		try:
			return json.loads(value)
		except json.JSONDecodeError:
			return None
	return None


def deterministic_reporting_callback(callback_context: CallbackContext):
	state = callback_context.state
	alert = _safe_json_loads(state.get("generated_log")) or {}
	triage = _safe_json_loads(state.get("triage_result")) or {}
	threat = _safe_json_loads(state.get("threat_intel_result")) or {}
	decision = _safe_json_loads(state.get("containment_decision")) or {}
	execution = _safe_json_loads(state.get("execution_result")) or {}
	correlation = triage.get("correlation_result") or _safe_json_loads(state.get("correlation_result")) or {}

	source_ip = alert.get("source_ip", "unknown")
	target_host = alert.get("target_host", "unknown-host")
	incident_id = f"{str(source_ip).replace('.', '-')}_{str(target_host).replace(' ', '-')[:20]}"

	logs = alert.get("logs", []) if isinstance(alert.get("logs", []), list) else []
	first_ts = logs[0].get("timestamp") if logs else "unknown"
	last_ts = logs[-1].get("timestamp") if logs else "unknown"
	timeline = (
		f"Observed {len(logs)} log events from {first_ts} to {last_ts}. "
		f"Primary attack type: {triage.get('attack_type', 'unknown')}."
	)

	protocols = sorted({str(log.get("protocol", "N/A")) for log in logs}) if logs else []
	affected_assets = (
		f"source_ip={source_ip}; target_host={target_host}; "
		f"protocols={', '.join(protocols) if protocols else 'N/A'}"
	)

	threat_intel_summary = (
		f"confidence_score={threat.get('confidence_score', 'N/A')}; "
		f"total_reports={threat.get('total_reports', 'N/A')}; "
		f"is_tor={threat.get('is_tor', 'N/A')}"
	)

	log_correlation = (
		f"previously_seen={correlation.get('previously_seen', 'N/A')}; "
		f"times_seen={correlation.get('times_seen', 'N/A')}; "
		f"pattern_detected={correlation.get('pattern_detected', 'N/A')}"
	)

	geolocation = (
		f"country={threat.get('country_code', 'N/A')}; "
		f"isp={threat.get('isp', 'N/A')}; "
		f"domain={threat.get('domain', 'N/A')}; "
		f"is_tor={threat.get('is_tor', 'N/A')}"
	)

	containment_actions = (
		f"decision_action={decision.get('action', 'N/A')}; "
		f"decision_confidence={decision.get('confidence', 'N/A')}; "
		f"execution_result={execution.get('result', execution.get('error', 'N/A'))}"
	)

	follow_up_steps = (
		"1) Validate indicators on affected host. "
		"2) Hunt for lateral movement. "
		"3) Tune detection rules from this incident."
	)

	result = save_incident_report(
		incident_id=incident_id,
		timeline=timeline,
		affected_assets=affected_assets,
		threat_intel_summary=threat_intel_summary,
		log_correlation=log_correlation,
		geolocation=geolocation,
		containment_actions=containment_actions,
		follow_up_steps=follow_up_steps,
	)
	callback_context.state["report_result"] = result
	return Content(parts=[Part(text=json.dumps(result))])


reporting_agent = SequentialAgent(
	name="ReportingAgent",
	description="Deterministic reporting agent.",
	before_agent_callback=deterministic_reporting_callback,
	sub_agents=[],
)
