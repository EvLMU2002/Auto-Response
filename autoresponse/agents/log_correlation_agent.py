from google.adk.agents import LlmAgent

from agents.data.historical_logs import HISTORICAL_LOGS

log_correlation_agent = LlmAgent(
    name="LogCorrelationAgent",
    model="gemini-2.0-flash",
    instruction=f"""
    You are a log correlation analyst.
    
    You have access to these historical logs:
    {HISTORICAL_LOGS}
    
    Extract the source_ip from 'generated_log' in session state.
    Check if this IP appears in the historical logs above.
    
    Return structured JSON with:
    - previously_seen (true/false)
    - times_seen
    - known_attack_types
    - last_seen_days_ago
    - pattern_detected (e.g. multi-stage reconnaissance)
    - confidence_boost (LOW / MEDIUM / HIGH)
    """,
    output_key="correlation_result"
)