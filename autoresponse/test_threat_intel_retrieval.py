import importlib
import json
import sys
import types
import unittest
from datetime import datetime

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from agents.log_generator import generate_mock_alert
from tools.threat_intel_server import check_abuseipdb


def format_logs_for_terminal(alert: dict) -> str:
    """Format generated logs for readable terminal output."""
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


def _install_orchestrator_import_aliases() -> None:
    """Make the current orchestrator importable from the package root for tests."""
    module_aliases = {
        "triage_agent": "agents.triage_agent",
        "threat_intel_agent": "agents.threat_intel_agent",
        "log_correlation_agent": "agents.log_correlation_agent",
        "containment_decision_agent": "agents.containment_decision_agent",
    }
    for bare_name, qualified_name in module_aliases.items():
        if bare_name not in sys.modules:
            sys.modules[bare_name] = importlib.import_module(qualified_name)

    stub_agents = {
        "containment_execution_agent": ("ContainmentExecutionAgent", "execution_result"),
        "reporting_agent": ("ReportingAgent", "report_result"),
    }
    for module_name, (agent_name, output_key) in stub_agents.items():
        if module_name in sys.modules:
            continue

        stub_module = types.ModuleType(module_name)
        stub_agent = LlmAgent(
            name=agent_name,
            model="gemini-2.0-flash",
            instruction="Stub agent used only to make the orchestrator importable during tests.",
            output_key=output_key,
        )
        setattr(stub_module, module_name, stub_agent)
        sys.modules[module_name] = stub_module


def load_orchestrator_name() -> str:
    """Load the configured orchestrator name when possible, otherwise use the declared name."""
    try:
        _install_orchestrator_import_aliases()
        orchestrator_module = importlib.import_module("agents.orchestrator")
        return orchestrator_module.orchestrator.name
    except Exception as error:
        print(f"[test] orchestrator import fallback: {error}")
        return "OrchestratorAgent"


def verify_generated_log(callback_context: CallbackContext):
    payload = callback_context.state.get("generated_log")
    if not payload:
        raise AssertionError("generated_log was not found in session state")

    alert = json.loads(payload)
    probe_summary = {
        "source_ip": alert["source_ip"],
        "target_host": alert["target_host"],
        "log_count": alert["log_count"],
        "first_event": alert["logs"][0]["event"],
    }

    print("[orchestrator] generated_log received from session state")
    print(json.dumps(probe_summary, indent=2))

    callback_context.state["probe_summary"] = probe_summary
    return Content(
        parts=[
            Part(
                text=(
                    "Verified generated_log handoff "
                    f"for {probe_summary['source_ip']} -> {probe_summary['target_host']}"
                )
            )
        ]
    )


class ThreatIntelRetrievalTest(unittest.IsolatedAsyncioTestCase):
    async def test_threat_intel_server_retrieval_from_generated_log(self):
        orchestrator_name = load_orchestrator_name()
        session_service = InMemorySessionService()

        app_name = "security_mas_threat_intel_test"
        user_id = "analyst_1"

        print("\n[test] generating mock alert")
        alert = serialize_log(generate_mock_alert())
        print(format_logs_for_terminal(alert))
        print()

        session = await session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            state={"generated_log": json.dumps(alert)},
        )
        print(f"[test] session created: {session.id}")
        print(f"[test] seeded generated_log for {orchestrator_name}")

        orchestrator_probe = SequentialAgent(
            name=orchestrator_name,
            description="Probe orchestrator for generated_log handoff before threat intel lookup",
            sub_agents=[],
            before_agent_callback=verify_generated_log,
        )
        runner = Runner(
            agent=orchestrator_probe,
            app_name=app_name,
            session_service=session_service,
        )

        responses = []
        print("[test] starting orchestrator handoff probe")
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=Content(parts=[Part(text="Validate generated_log handoff for threat intel retrieval.")]),
        ):
            if not event.content:
                continue
            responses.extend(
                part.text
                for part in event.content.parts
                if getattr(part, "text", None)
            )
        print("[test] orchestrator handoff probe completed")

        final_session = await session_service.get_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session.id,
        )
        probe_summary = final_session.state.get("probe_summary")
        print("[test] passing of results confirmed")
        print(json.dumps(probe_summary, indent=2))

        source_ip = probe_summary["source_ip"]
        print(f"[test] invoking threat_intel_server with source_ip: {source_ip}")
        print("[test] raw AbuseIPDB response from threat_intel_server follows")
        threat_intel_result = await check_abuseipdb(source_ip)
        print("[test] normalized threat_intel_server result")
        print(json.dumps(threat_intel_result, indent=2))

        self.assertIsNotNone(probe_summary)
        self.assertEqual(probe_summary["source_ip"], alert["source_ip"])
        self.assertEqual(probe_summary["target_host"], alert["target_host"])
        self.assertEqual(probe_summary["log_count"], alert["log_count"])
        self.assertEqual(probe_summary["first_event"], alert["logs"][0]["event"])
        self.assertTrue(
            any("Verified generated_log handoff" in response for response in responses)
        )
        self.assertIsInstance(threat_intel_result, dict)
        self.assertEqual(threat_intel_result.get("ip_address"), source_ip)
        self.assertIn("confidence_score", threat_intel_result)
        self.assertIn("reports", threat_intel_result)


if __name__ == "__main__":
    unittest.main()