import json
import os

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

mcp = FastMCP("ThreatIntelServer")
load_dotenv()


def _format_report(report: dict) -> dict:
    return {
        "reported_at": report.get("reportedAt"),
        "comment": report.get("comment"),
        "categories": report.get("categories", []),
        "reporter_id": report.get("reporterId"),
        "reporter_country_code": report.get("reporterCountryCode"),
        "reporter_country_name": report.get("reporterCountryName"),
    }

@mcp.tool()
async def check_abuseipdb(ip_address: str) -> dict:
    """Query AbuseIPDB for threat intelligence on an IP address."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY is not set. Add it to your environment or .env file.")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": 90}
        )
    response.raise_for_status()

    response_payload = response.json()
    print("[threat_intel_server] AbuseIPDB raw response:")
    print(json.dumps(response_payload, indent=2))

    data = response_payload.get("data", {})
    return {
        "ip_address": data.get("ipAddress"),
        "is_public": data.get("isPublic"),
        "ip_version": data.get("ipVersion"),
        "is_whitelisted": data.get("isWhitelisted"),
        "confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames", []),
        "is_tor": data.get("isTor"),
        "total_reports": data.get("totalReports"),
        "num_distinct_users": data.get("numDistinctUsers"),
        "last_reported_at": data.get("lastReportedAt"),
        "reports": [_format_report(report) for report in data.get("reports", [])],
    }

if __name__ == "__main__":
    mcp.run()