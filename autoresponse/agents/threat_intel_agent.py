from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from mcp import StdioServerParameters

threat_intel_agent = LlmAgent(
    name="ThreatIntelAgent",
    model="gemini-2.0-flash",
    instruction="""
    You are a threat intelligence analyst.
    
    Extract the source_ip from 'generated_log' in session state.
    Use the available MCP tool to query AbuseIPDB threat intelligence on that IP.
    
    Return findings as structured JSON with detailed AbuseIPDB results.
    Include these fields when available:
    - ip_address
    - is_public
    - ip_version
    - is_whitelisted
    - confidence_score
    - country_code
    - country_name
    - usage_type
    - isp
    - domain
    - hostnames
    - is_tor
    - total_reports
    - num_distinct_users
    - last_reported_at
    - reports

    Also include a concise threat_summary that explains the most important findings.
    """,
    output_key="threat_intel_result",
    tools=[
        MCPToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="python",
                    args=["tools/threat_intel_server.py"]  # path to your FastMCP server
                )
            )
        )
    ]
)