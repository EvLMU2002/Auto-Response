import asyncio 
import json 
import os
from dotenv import load_dotenv
from google.adk.sessions import InMemorySessionService 
from google.adk.runners import Runner 
from google.genai.types import Content, Part 
 
from agents.log_generator import generate_mock_alert 
from agents.orchestrator import orchestrator 
from agents.threat_intel_agent import threat_intel_agent 
 
 
def serialize_log(alert: dict) -> dict: 
   """Convert datetime objects to strings for session state storage.""" 
   serialized = alert.copy() 
   serialized["logs"] = [ 
       {**log, "timestamp": log["timestamp"].isoformat()} 
       for log in alert["logs"] 
   ] 
   return serialized 
 
 
async def run_security_pipeline(): 
   load_dotenv()
   if not os.getenv("GOOGLE_API_KEY") and os.getenv("GEMINI_API_KEY"):
       os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]

   if not os.getenv("GOOGLE_API_KEY"):
       raise RuntimeError(
           "Missing GOOGLE_API_KEY (or GEMINI_API_KEY). Add it to .env or set it in your shell before running main.py."
       )

   session_service = InMemorySessionService() 
 
   APP_NAME = "security_mas" 
   USER_ID  = "analyst_1" 
 
   # ── Step 1: Generate alert from log generator program ───────────────── 
   print("=== Step 1: Generating attack log ===") 
   raw_alert = generate_mock_alert() 
   alert     = serialize_log(raw_alert) 
   print(f"Alert generated | IP: {alert['source_ip']} | " 
         f"Host: {alert['target_host']} | Logs: {alert['log_count']}\n") 
 
   # ── Step 2: Create session, seed state with alert ───────────────────── 
   session = await session_service.create_session( 
       app_name=APP_NAME, 
       user_id=USER_ID, 
       state={"generated_log": json.dumps(alert)} 
   ) 
 
   # ── Step 3: Run full pipeline ────────────────────────────────────────── 
   runner = Runner( 
       agent=orchestrator, 
       app_name=APP_NAME, 
       session_service=session_service 
   ) 

   try:
       print("=== Step 2: Running security pipeline ===") 
       print("  [PARALLEL]  Triage+Correlation | Threat Intel") 
       print("  [SEQUENTIAL] Containment Decision") 
       print("  [PARALLEL]  Containment Execution | Reporting\n") 
 
       async for event in runner.run_async( 
           user_id=USER_ID, 
           session_id=session.id, 
           new_message=Content(parts=[Part(text="Begin security analysis and containment pipeline.")]) 
       ): 
           if event.is_final_response(): 
               print(f"Pipeline complete:\n{event.content}\n") 

       # ── Print final session state summary ───────────────────────────── 
       final_session = await session_service.get_session( 
           app_name=APP_NAME, 
           user_id=USER_ID, 
           session_id=session.id 
       ) 
 
       report_result = final_session.state.get("report_result", {}) 
       execution_result = final_session.state.get("execution_result", {}) 
 
       print("=== Pipeline Summary ===") 
       print(f"Containment action : {final_session.state.get('containment_decision', {})}") 
       print(f"Execution result   : {execution_result.get('result', 'N/A')}") 
       print(f"Report saved to    : {report_result.get('file_path', 'N/A')}") 
   finally:
       # Ensure MCP toolsets are closed when the run finishes or errors.
       for tool in getattr(threat_intel_agent, "tools", []):
           close = getattr(tool, "close", None)
           if close:
               await close()
 
 
if __name__ == "__main__": 
   asyncio.run(run_security_pipeline())