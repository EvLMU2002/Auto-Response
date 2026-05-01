import json
import re
import os
from pathlib import Path

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.genai.types import Content, Part

from tools.reporting_tool import save_incident_report
from agents.data.historical_logs import HISTORICAL_LOGS


def _persist_historical_logs():
	"""Write updated HISTORICAL_LOGS back to the file."""
	logs_file = Path(__file__).parent / "data" / "historical_logs.py"
	
	# Format as Python code
	content = "HISTORICAL_LOGS = [\n"
	for entry in HISTORICAL_LOGS:
		content += f'    {{"ip": "{entry["ip"]}", "event": "{entry["event"]}", "occurrences": {entry["occurrences"]}}},\n'
	content += "]\n"
	
	logs_file.write_text(content)


def _safe_json_loads(value):
	if isinstance(value, dict):
		return value
	if not isinstance(value, str):
		return None

	text = value.strip()
	# Handle fenced JSON blocks like ```json ... ```
	fenced_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL | re.IGNORECASE)
	if fenced_match:
		text = fenced_match.group(1).strip()

	try:
		return json.loads(text)
	except json.JSONDecodeError:
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

	# Save or update historical logs based on IP and event
	if source_ip != "unknown":
		attack_type = triage.get("attack_type", "unknown")
		
		# Look for exact match (same IP and same event)
		exact_match = None
		for entry in HISTORICAL_LOGS:
			if entry.get("ip") == source_ip and entry.get("event") == attack_type:
				exact_match = entry
				break
		
		if exact_match:
			# Increment occurrences for existing IP+event combination
			exact_match["occurrences"] = exact_match.get("occurrences", 1) + 1
		else:
			# New IP or new event for existing IP
			new_entry = {"ip": source_ip, "event": attack_type, "occurrences": 1}
			HISTORICAL_LOGS.append(new_entry)
		
		# Persist changes back to file
		_persist_historical_logs()
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
