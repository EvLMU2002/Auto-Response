import os

from google.adk.agents import LlmAgent



triage_agent = LlmAgent(
    name="TriageAgent",
    model="gemini-2.5-flash",
    instruction=f"""
    You are a security triage analyst.
    
    You will receive a security log from session state under 'generated_log'.

    Runtime context from session state:
    generated_log:
    {{generated_log}}

  

    Analyze it and determine:
    - Severity level (LOW / MEDIUM / HIGH / CRITICAL)
    - True Positive or False Positive

        Output requirements:
        - Return exactly one raw JSON object.
        - Do NOT wrap the JSON in markdown or code fences.
        - Do NOT include any explanation outside JSON.
        - Use exactly these keys:
            severity, true_positive, analysis

        JSON schema:
        {{
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "true_positive": true,
            "analysis": "1-3 concise sentences"
        }}
    """,
    output_key="triage_result"
)