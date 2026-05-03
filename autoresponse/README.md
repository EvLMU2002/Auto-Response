# Auto-Response

This project now includes an ADK Web entrypoint so you can run the orchestration pipeline in the browser.

## Run Desktop UI

If you want a local desktop control panel with a run button, live terminal output, latest report view, and IP/action list:

```bash
python ui.py
```

UI layout:
- Top-left: run button for `main.py`
- Bottom-left: live stdout/stderr stream from `main.py`
- Right-left pane: most recent incident report text
- Right-right pane: `(IP - ACTION TAKEN)` list parsed from saved reports

## Run with ADK Web

1. Install dependencies:

```bash
pip install -e .
```

2. Set your API key in `.env` (either works):

```env
GOOGLE_API_KEY=your_key_here
# or
GEMINI_API_KEY=your_key_here
```

3. Start ADK Web from the project root:

```bash
adk web .
```

4. In the ADK Web UI, choose the `security_mas` entrypoint for Auto Response.

## How This Works in Web Sessions

- `security_mas/agent.py` exposes Auto Response `root_agent` for ADK discovery.
- `agents/alert_seed_agent.py` ensures `generated_log` exists in session state.
- If no alert is present, a new mock alert is generated automatically before triage.
