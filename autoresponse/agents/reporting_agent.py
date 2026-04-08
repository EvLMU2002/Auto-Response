from google.adk.agents import LlmAgent

from tools.reporting_tool import reporting_tool


reporting_agent = LlmAgent(
	name="ReportingAgent",
	model="gemini-2.0-flash",
	instruction="""
	You are a reporting agent for a security operations workflow.

	Read these keys from session state:
	- generated_log
	- triage_result
	- threat_intel_result
	- correlation_result
	- containment_decision
	- execution_result

	Create a concise incident report and call the reporting tool exactly once.

	Build tool arguments as follows:
	- incident_id: derive a short ID from the source IP and target host
	- timeline: summarize the log sequence and timestamps
	- affected_assets: include source IP, target host, and notable ports or protocols
	- threat_intel_summary: summarize AbuseIPDB findings and risk level
	- log_correlation: summarize prior sightings and attack patterns
	- geolocation: include country, ISP, domain, and Tor status when available
	- containment_actions: summarize containment_decision and execution_result
	- follow_up_steps: provide short analyst next steps

	Return only valid JSON matching the reporting tool result.
	""",
	output_key="report_result",
	tools=[reporting_tool],
)
