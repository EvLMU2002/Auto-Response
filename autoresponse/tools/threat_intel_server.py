import json
import ipaddress
import os
import time

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

mcp = FastMCP("ThreatIntelServer")
load_dotenv()

_CACHE: dict[str, tuple[float, dict]] = {}


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
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return {
            "error": "invalid_ip",
            "message": f"Invalid IP address: {ip_address}",
            "ip_address": ip_address,
        }

    # Reduce unnecessary external calls for IPs that are not globally routable threat intel targets.
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
        return {
            "ip_address": ip_address,
            "is_public": False,
            "ip_version": ip_obj.version,
            "is_whitelisted": None,
            "confidence_score": 0,
            "country_code": None,
            "country_name": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "hostnames": [],
            "is_tor": False,
            "total_reports": 0,
            "num_distinct_users": 0,
            "last_reported_at": None,
            "reports": [],
            "threat_summary": "Lookup skipped for non-public IP",
        }

    ttl_seconds = int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "600"))
    now = time.time()
    cached = _CACHE.get(ip_address)
    if cached and cached[0] > now:
        return cached[1]

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
    result = {
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
    _CACHE[ip_address] = (now + ttl_seconds, result)
    return result

if __name__ == "__main__":
    mcp.run()