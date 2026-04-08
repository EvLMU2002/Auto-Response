from google.adk.agents import LlmAgent

triage_agent = LlmAgent(
    name="TriageAgent",
    model="gemini-2.0-flash",
    instruction="""
    You are a security triage analyst.
    
    You will receive a security log from session state under 'generated_log'.
    
    Analyze it and determine:
    - Is this a real attack or scanner noise?
    - Severity level (LOW / MEDIUM / HIGH / CRITICAL)
    - True Positive or False Positive
    - Reasoning for your decision
    
    Consider failed login counts, timeframes, and any recon patterns.
    Return your findings as structured JSON.
    """,
    output_key="triage_result"
)