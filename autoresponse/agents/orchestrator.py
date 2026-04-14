from google.adk.agents import ParallelAgent, SequentialAgent

from agents.correlation_agent import correlation_agent
from agents.containment_decision_agent import containment_decision_agent
from agents.containment_execution_agent import containment_execution_agent
from agents.reporting_agent import reporting_agent
from agents.threat_intel_agent import threat_intel_agent
from agents.triage_agent import triage_agent


parallel_analysis = ParallelAgent(
    name="ParallelAnalysis",
    sub_agents=[triage_agent, correlation_agent, threat_intel_agent],
)


parallel_containment = ParallelAgent(
    name="ParallelContainment",
    sub_agents=[containment_execution_agent, reporting_agent],
)


orchestrator = SequentialAgent(
    name="OrchestratorAgent",
    description=(
        "Runs triage, correlation, and threat intel in parallel, makes a containment decision, "
        "then executes containment and reporting in parallel."
    ),
    sub_agents=[
        parallel_analysis,
        containment_decision_agent,
        parallel_containment,
    ],
)