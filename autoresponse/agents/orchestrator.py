from google.adk.agents import ParallelAgent, SequentialAgent, LlmAgent
from triage_agent import triage_agent
from threat_intel_agent import threat_intel_agent
from log_correlation_agent import log_correlation_agent
from containment_decision_agent import containment_decision_agent
from containment_execution_agent import containment_execution_agent
from reporting_agent import reporting_agent

# Stage 1 — all 3 run in parallel
parallel_analysis = ParallelAgent(
    name="ParallelAnalysis",
    sub_agents=[triage_agent, threat_intel_agent, log_correlation_agent]
)

# Stage 2 — execution and reporting run in parallel after decision
parallel_containment = ParallelAgent(
    name="ParallelContainment",
    sub_agents=[containment_execution_agent, reporting_agent]
)

# Orchestrator wraps the parallel execution and makes final decision
orchestrator = SequentialAgent(
    name="OrchestratorAgent",
    model="gemini-2.0-flash",
    instruction="""
    You are a security orchestrator.
    Your job is to Coordinates the full security incident response pipeline:

    1. Runs triage, threat intel, and log correlation in parallel
    2. Passes enriched results to the containment decision agent
    3. Runs containment execution and reporting in parallel
    """,
    output_key="final_report",
    sub_agents=[parallel_analysis, containment_decision_agent, parallel_containment]
)