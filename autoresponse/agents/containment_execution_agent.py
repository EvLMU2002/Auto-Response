from google.adk.agents import LlmAgent
from tools.firewall_tool import firewall_tool

containment_execution_agent = LlmAgent(
    name="ContainmentExecutionAgent",
    model="gemini-2.0-flash",
    instruction="""
    You are a containment execution agent.

    Read 'containment_decision' from session state. It contains:
    - action
    - target
    - reason
    - confidence

    Immediately call execute_containment with the action, target, and reason.

    After execution, save the full result to session state key 'execution_result'.
    """,
    output_key="execution_result",
    tools=[firewall_tool]
)