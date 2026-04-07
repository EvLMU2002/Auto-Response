import json
import unittest

from google.adk.agents import SequentialAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from agents.log_generator import generate_mock_alert

from datetime import datetime
import json

# to test orchestrator receives generated_log from session state
# run this in autoresponse dir: .venv\Scripts\python.exe -m unittest discover -v


def format_logs_for_terminal(alert: dict) -> str:
    """Format output from generate_mock_alert() for readable terminal display."""
    formatted_logs = []
    for idx, log in enumerate(alert.get("logs", []), start=1):
        entry = dict(log)
        timestamp = entry.get("timestamp")
        if isinstance(timestamp, datetime):
            entry["timestamp"] = timestamp.isoformat(sep=" ", timespec="seconds")
        entry["index"] = idx
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
        {**log, "timestamp": log["timestamp"].isoformat()}
        for log in alert["logs"]
    ]
    return serialized


def verify_generated_log(callback_context: CallbackContext):
    payload = callback_context.state.get("generated_log")
    if not payload:
        raise AssertionError("generated_log was not found in session state")

    print("[callback] generated_log found in session state")
    alert = json.loads(payload)
    print(
        "[callback] parsed alert:",
        {
            "source_ip": alert["source_ip"],
            "target_host": alert["target_host"],
            "log_count": alert["log_count"],
            "first_event": alert["logs"][0]["event"],
        },
    )
    callback_context.state["probe_summary"] = {
        "source_ip": alert["source_ip"],
        "target_host": alert["target_host"],
        "log_count": alert["log_count"],
        "first_event": alert["logs"][0]["event"],
    }

    return Content(
        parts=[
            Part(
                text=(
                    "Verified generated_log handoff "
                    f"for {alert['source_ip']} -> {alert['target_host']}"
                )
            )
        ]
    )


class OrchestratorLogHandoffTest(unittest.IsolatedAsyncioTestCase):
    async def test_orchestrator_receives_generated_log_from_session_state(self):
        app_name = "security_mas_test"
        user_id = "analyst_1"
        session_service = InMemorySessionService()

        print("\n[test] generating mock alert")
        alert = serialize_log(generate_mock_alert())
        print(format_logs_for_terminal(alert))
        print()
        print()
        
        print(
            "[test] generated alert summary:",
            {
                "source_ip": alert["source_ip"],
                "target_host": alert["target_host"],
                "log_count": alert["log_count"],
                "first_event": alert["logs"][0]["event"],
            },
        )
        session = await session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            state={"generated_log": json.dumps(alert)},
        )
        print(f"[test] session created: {session.id}")
        print("[test] generated_log seeded into session state")

        orchestrator_probe = SequentialAgent(
            name="OrchestratorAgent",
            description="Probe orchestrator for generated_log handoff",
            sub_agents=[],
            before_agent_callback=verify_generated_log,
        )
        print("[test] orchestrator probe initialized")
        runner = Runner(
            agent=orchestrator_probe,
            app_name=app_name,
            session_service=session_service,
        )
        print("[test] runner initialized")

        responses = []
        print("[test] starting runner")
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=Content(parts=[Part(text="Validate generated_log handoff.")]),
        ):
            if event.content:
                print("[test] runner event content received")
                responses.extend(
                    part.text
                    for part in event.content.parts
                    if getattr(part, "text", None)
                )
        print("[test] runner completed")

        final_session = await session_service.get_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session.id,
        )
        probe_summary = final_session.state.get("probe_summary")
        print("[test] final probe_summary:", probe_summary)
        print("[test] responses:", responses)

        self.assertIsNotNone(probe_summary)
        self.assertEqual(probe_summary["source_ip"], alert["source_ip"])
        self.assertEqual(probe_summary["target_host"], alert["target_host"])
        self.assertEqual(probe_summary["log_count"], alert["log_count"])
        self.assertEqual(probe_summary["first_event"], alert["logs"][0]["event"])
        self.assertTrue(
            any("Verified generated_log handoff" in response for response in responses)
        )


if __name__ == "__main__":
    unittest.main()