import json
import unittest
from datetime import datetime

from google.adk.agents import ParallelAgent, SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from agents.containment_decision_agent import CONTAINMENT_TIERS, containment_decision_agent
from agents.data.historical_logs import HISTORICAL_LOGS
from agents.log_generator import generate_mock_alert
from agents.orchestrator import orchestrator
from agents.threat_intel_agent import threat_intel_agent
from agents.triage_agent import triage_agent
from tools.threat_intel_server import check_abuseipdb


TIER_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def format_logs_for_terminal(alert: dict) -> str:
    formatted_logs = []
    for index, log in enumerate(alert.get("logs", []), start=1):
        entry = dict(log)
        timestamp = entry.get("timestamp")
        if isinstance(timestamp, datetime):
            entry["timestamp"] = timestamp.isoformat(sep=" ", timespec="seconds")
        entry["index"] = index
        formatted_logs.append(entry)

    formatted_alert = {
        "source_ip": alert.get("source_ip"),
        "target_host": alert.get("target_host"),
        "log_count": alert.get("log_count"),
        "time_window_seconds": alert.get("time_window_seconds"),
        "logs": formatted_logs,
    }
    return json.dumps(formatted_alert, indent=2)


def serialize_log(alert: dict) -> dict:
    serialized = alert.copy()
    serialized["logs"] = [
        {
            **log,
            "timestamp": (
                log["timestamp"].isoformat()
                if isinstance(log.get("timestamp"), datetime)
                else log.get("timestamp")
            ),
        }
        for log in alert.get("logs", [])
    ]
    return serialized


def _tier_to_index(tier: str) -> int:
    tier = (tier or "LOW").upper()
    return TIER_ORDER.index(tier) if tier in TIER_ORDER else 0


def _index_to_tier(index: int) -> str:
    return TIER_ORDER[max(0, min(index, len(TIER_ORDER) - 1))]


def derive_triage_result(alert: dict) -> dict:
    logs = alert.get("logs", [])
    events = [str(log.get("event", "")).upper() for log in logs]
    messages = [str(log.get("message", "")).lower() for log in logs]
    protocols = sorted({str(log.get("protocol", "N/A")) for log in logs})
    log_count = len(logs)

    severity = "LOW"
    disposition = "FALSE POSITIVE"
    attack_type = "scanner_noise"
    reasoning = []

    if any("encrypt" in message or "ransom" in message for message in messages):
        severity = "CRITICAL"
        disposition = "TRUE POSITIVE"
        attack_type = "ransomware"
        reasoning.append("File encryption or ransomware behavior was present in the generated logs.")
    elif any(
        marker in message
        for message in messages
        for marker in [
            "trojan",
            "c2",
            "credential harvest",
            "phishing",
            "union select",
            "drop table",
            "sleep(",
            "malicious payload",
        ]
    ):
        severity = "HIGH"
        disposition = "TRUE POSITIVE"
        attack_type = "application_attack"
        reasoning.append("The generated logs contain explicit malicious payload or post-exploitation indicators.")
    elif events.count("AUTH_FAILURE") >= 8:
        severity = "HIGH"
        disposition = "TRUE POSITIVE"
        attack_type = "brute_force"
        reasoning.append("Repeated authentication failures indicate a brute-force pattern rather than background noise.")
    elif events.count("CONNECTION_ATTEMPT") >= 10:
        severity = "LOW"
        disposition = "FALSE POSITIVE"
        attack_type = "port_scan"
        reasoning.append("The activity looks like reconnaissance or scanner noise with repeated connection attempts.")
    elif log_count >= 4:
        severity = "MEDIUM"
        disposition = "TRUE POSITIVE"
        attack_type = "suspicious_activity"
        reasoning.append("The generated log volume and event pattern suggest a real security event.")
    else:
        reasoning.append("The event stream is limited and currently resembles low-confidence noise.")

    return {
        "severity": severity,
        "disposition": disposition,
        "attack_type": attack_type,
        "reasoning": " ".join(reasoning),
        "log_count": log_count,
        "protocols": protocols,
    }


def derive_correlation_result(source_ip: str) -> dict:
    matches = [entry for entry in HISTORICAL_LOGS if entry.get("ip") == source_ip]
    if not matches:
        return {
            "previously_seen": False,
            "times_seen": 0,
            "known_attack_types": [],
            "last_seen_days_ago": None,
            "pattern_detected": "no historical match",
            "confidence_boost": "LOW",
        }

    return {
        "previously_seen": True,
        "times_seen": len(matches),
        "known_attack_types": sorted({entry.get("event") for entry in matches}),
        "last_seen_days_ago": min(entry.get("days_ago", 0) for entry in matches),
        "pattern_detected": "repeat offender",
        "confidence_boost": "HIGH" if len(matches) > 1 else "MEDIUM",
    }


def decide_containment_action(alert: dict, triage_result: dict, threat_intel_result: dict, correlation_result: dict) -> dict:
    base_severity = str(triage_result.get("severity", "LOW")).upper()
    final_index = _tier_to_index(base_severity)
    escalation_factors = []

    confidence_score = int(threat_intel_result.get("confidence_score") or 0)
    is_tor = bool(threat_intel_result.get("is_tor"))
    is_whitelisted = bool(threat_intel_result.get("is_whitelisted"))
    previously_seen = bool(correlation_result.get("previously_seen"))
    known_attack_types = correlation_result.get("known_attack_types") or []
    pattern_detected = str(correlation_result.get("pattern_detected") or "")

    if confidence_score > 80:
        final_index += 1
        escalation_factors.append("abuse_confidence_gt_80")
    if is_tor:
        final_index += 1
        escalation_factors.append("tor_exit_node")
    if "multi-stage" in pattern_detected.lower():
        final_index += 1
        escalation_factors.append("multi_stage_reconnaissance")
    if previously_seen and known_attack_types:
        final_index += 1
        escalation_factors.append("known_attack_history")

    severity_tier = _index_to_tier(final_index)
    overall_confidence = "LOW"
    evidence_score = 0
    if str(triage_result.get("disposition", "")).upper() == "TRUE POSITIVE":
        evidence_score += 1
    if confidence_score >= 50 or is_tor:
        evidence_score += 1
    if previously_seen:
        evidence_score += 1

    if evidence_score >= 3:
        overall_confidence = "HIGH"
    elif evidence_score == 2:
        overall_confidence = "MEDIUM"

    if str(triage_result.get("disposition", "")).upper() == "FALSE POSITIVE":
        severity_tier = "LOW"
        overall_confidence = "LOW"
        escalation_factors = ["triage_false_positive"]

    if overall_confidence == "LOW" and severity_tier != "LOW":
        severity_tier = _index_to_tier(_tier_to_index(severity_tier) - 1)

    candidate_actions = CONTAINMENT_TIERS[severity_tier]
    action = candidate_actions[0]

    if severity_tier == "MEDIUM" and overall_confidence == "HIGH" and not is_whitelisted:
        action = "BLOCK_IP"
    elif severity_tier == "HIGH":
        action = "PAUSE" if is_whitelisted else "NETWORK_ISOLATE"
    elif severity_tier == "CRITICAL":
        action = "SNAPSHOT" if is_whitelisted else "QUARANTINE"
    elif severity_tier == "LOW":
        action = "MONITOR"

    reasoning_parts = [
        f"Triage rated the activity as {base_severity} with disposition {triage_result.get('disposition')}",
        f"AbuseIPDB confidence score was {confidence_score}",
        f"historical correlation status was {correlation_result.get('pattern_detected')}",
    ]

    if is_whitelisted:
        reasoning_parts.append(
            "the IP is whitelisted, so it was treated as contextual information rather than automatic trust"
        )

    return {
        "action": action,
        "target": alert.get("source_ip"),
        "reason": "; ".join(reasoning_parts),
        "confidence": overall_confidence,
        "severity_tier": severity_tier,
        "escalation_factors": escalation_factors,
        "base_severity": base_severity,
    }


def verify_generated_log(callback_context: CallbackContext):
    payload = callback_context.state.get("generated_log")
    if not payload:
        raise AssertionError("generated_log was not found in session state")

    alert = json.loads(payload)
    print("[orchestrator] handing generated_log to downstream analysis agents")
    print(
        json.dumps(
            {
                "source_ip": alert.get("source_ip"),
                "target_host": alert.get("target_host"),
                "log_count": alert.get("log_count"),
            },
            indent=2,
        )
    )
    return None


def triage_probe(callback_context: CallbackContext):
    alert = json.loads(callback_context.state["generated_log"])
    print("[triage] received generated_log from orchestrator")
    triage_result = derive_triage_result(alert)
    callback_context.state["triage_result"] = triage_result
    print("[triage] triage_result")
    print(json.dumps(triage_result, indent=2))
    return Content(parts=[Part(text=json.dumps(triage_result))])


async def threat_intel_probe(callback_context: CallbackContext):
    alert = json.loads(callback_context.state["generated_log"])
    source_ip = alert["source_ip"]
    print(f"[threat_intel] received generated_log from orchestrator for IP: {source_ip}")
    print("[threat_intel] raw response from threat_intel_server follows")
    threat_intel_result = await check_abuseipdb(source_ip)
    callback_context.state["threat_intel_result"] = threat_intel_result
    print("[threat_intel] normalized threat_intel_result")
    print(json.dumps(threat_intel_result, indent=2))
    return Content(parts=[Part(text=json.dumps(threat_intel_result))])


def containment_decision_probe(callback_context: CallbackContext):
    alert = json.loads(callback_context.state["generated_log"])
    triage_result = callback_context.state.get("triage_result")
    threat_intel_result = callback_context.state.get("threat_intel_result")
    correlation_result = callback_context.state.get("correlation_result")

    if not triage_result or not threat_intel_result:
        raise AssertionError("Containment decision probe did not receive triage_result and threat_intel_result")

    print("[containment_decision] received upstream analysis results")
    print(json.dumps({"triage_result": triage_result}, indent=2))
    print(json.dumps({"threat_intel_result": threat_intel_result}, indent=2))
    print(json.dumps({"correlation_result": correlation_result}, indent=2))

    containment_decision = decide_containment_action(
        alert,
        triage_result,
        threat_intel_result,
        correlation_result,
    )
    callback_context.state["containment_decision"] = containment_decision

    print("[containment_decision] decision output")
    print(json.dumps(containment_decision, indent=2))
    print(
        "[containment_decision] action that would be passed to execution agent: "
        f"{containment_decision['action']} -> {containment_decision['target']}"
    )

    return Content(parts=[Part(text=json.dumps(containment_decision))])


class OrchestratorDecisionHandoffTest(unittest.IsolatedAsyncioTestCase):
    async def test_orchestrator_hands_results_to_containment_decision(self):
        app_name = "security_mas_decision_handoff_test"
        user_id = "analyst_1"
        session_service = InMemorySessionService()

        print("\n[test] generating mock alert for orchestrator decision handoff")
        alert = serialize_log(generate_mock_alert())
        print(format_logs_for_terminal(alert))
        print()

        correlation_result = derive_correlation_result(alert["source_ip"])
        print("[test] seeded correlation_result for containment decision context")
        print(json.dumps(correlation_result, indent=2))

        session = await session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            state={
                "generated_log": json.dumps(alert),
                "correlation_result": correlation_result,
            },
        )
        print(f"[test] session created: {session.id}")

        triage_probe_agent = triage_agent.clone(update={"before_agent_callback": triage_probe})
        threat_intel_probe_agent = threat_intel_agent.clone(update={"before_agent_callback": threat_intel_probe})
        containment_decision_probe_agent = containment_decision_agent.clone(
            update={"before_agent_callback": containment_decision_probe}
        )

        parallel_analysis_probe = ParallelAgent(
            name="ParallelAnalysis",
            sub_agents=[triage_probe_agent, threat_intel_probe_agent],
        )

        decision_path_orchestrator = SequentialAgent(
            name=orchestrator.name,
            description="Test orchestrator path through triage, threat intel, and containment decision only.",
            before_agent_callback=verify_generated_log,
            sub_agents=[parallel_analysis_probe, containment_decision_probe_agent],
        )

        runner = Runner(
            agent=decision_path_orchestrator,
            app_name=app_name,
            session_service=session_service,
        )

        print("[test] starting orchestrator decision handoff run")
        async for _event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=Content(
                parts=[Part(text="Run the orchestrator handoff through containment decision only.")]
            ),
        ):
            pass
        print("[test] orchestrator decision handoff run completed")

        final_session = await session_service.get_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session.id,
        )

        triage_result = final_session.state.get("triage_result")
        threat_intel_result = final_session.state.get("threat_intel_result")
        containment_decision = final_session.state.get("containment_decision")

        print("[test] final triage_result")
        print(json.dumps(triage_result, indent=2))
        print("[test] final threat_intel_result")
        print(json.dumps(threat_intel_result, indent=2))
        print("[test] final containment_decision")
        print(json.dumps(containment_decision, indent=2))

        self.assertIsNotNone(triage_result)
        self.assertIsNotNone(threat_intel_result)
        self.assertIsNotNone(containment_decision)
        self.assertEqual(containment_decision.get("target"), alert["source_ip"])
        self.assertIn(containment_decision.get("action"), sum(CONTAINMENT_TIERS.values(), []))
        self.assertIn(containment_decision.get("severity_tier"), TIER_ORDER)


if __name__ == "__main__":
    unittest.main()