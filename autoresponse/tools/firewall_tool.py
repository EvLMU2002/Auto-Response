from google.adk.tools import FunctionTool
from datetime import datetime
import json
from pathlib import Path

# Load persistent firewall state
try:
    from agents.data.firewall_state import FIREWALL_STATE
except ImportError:
    FIREWALL_STATE = {
        "blocked_ips":       [],
        "blocked_ports":     [],
        "rate_limited_ips":  [],
        "isolated_hosts":    [],
        "stopped_services":  [],
        "paused_processes":  [],
        "snapshots":         [],
        "quarantined_hosts": [],
        "network_stopped_count": 0
    }

def _persist_firewall_state():
    """Write updated FIREWALL_STATE back to the file."""
    state_file = Path(__file__).parent.parent / "agents" / "data" / "firewall_state.py"
    
    # Format as Python code
    content = "# Auto-generated firewall state\n# Do not edit manually unless you know what you're doing.\n\n"
    content += f"FIREWALL_STATE = {json.dumps(FIREWALL_STATE, indent=4)}\n"
    
    state_file.write_text(content)

def execute_containment(action: str, target: str, reason: str) -> dict:
    """
    Execute a containment action against the mock firewall/network.
    
    Args:
        action: One of MONITOR, RATE_LIMIT, BLOCK_PORT, BLOCK_IP,
                DISABLE_SERVICE, NETWORK_ISOLATE, PAUSE, SNAPSHOT,
                QUARANTINE, STOP
        target: IP address, port, host, or service name
        reason: Why this action is being taken
    
    Returns:
        dict with action result and updated firewall state summary
    """
    action = action.upper()
    timestamp = datetime.now().isoformat()

    action_map = {
        "MONITOR": (
            lambda: None,
            f"Increased logging enabled for {target}"
        ),
        "RATE_LIMIT": (
            lambda: FIREWALL_STATE["rate_limited_ips"].append(target),
            f"Rate limiting applied to {target}"
        ),
        "BLOCK_PORT": (
            lambda: FIREWALL_STATE["blocked_ports"].append(target),
            f"Port {target} blocked at firewall"
        ),
        "BLOCK_IP": (
            lambda: FIREWALL_STATE["blocked_ips"].append(target),
            f"IP {target} blocked at firewall"
        ),
        "DISABLE_SERVICE": (
            lambda: FIREWALL_STATE["stopped_services"].append(target),
            f"Service {target} disabled"
        ),
        "NETWORK_ISOLATE": (
            lambda: FIREWALL_STATE["isolated_hosts"].append(target),
            f"Host {target} isolated from all networks"
        ),
        "PAUSE": (
            lambda: FIREWALL_STATE["paused_processes"].append(target),
            f"All processes on {target} frozen for forensic preservation"
        ),
        "SNAPSHOT": (
            lambda: FIREWALL_STATE["snapshots"].append(
                {"target": target, "timestamp": timestamp}
            ),
            f"Network snapshot committed for {target}"
        ),
        "QUARANTINE": (
            lambda: FIREWALL_STATE["quarantined_hosts"].append(target),
            f"Host {target} moved to isolated network"
        ),
        "STOP": (
            lambda: FIREWALL_STATE.update({"network_stopped_count": FIREWALL_STATE.get("network_stopped_count", 0) + 1}),
            f"Full network stop initiated — all traffic halted"
        ),
    }

    if action not in action_map:
        return {
            "success": False,
            "error":   f"Unknown action: {action}",
            "timestamp": timestamp
        }

    fn, result_msg = action_map[action]
    fn()
    _persist_firewall_state()

    return {
        "success":        True,
        "action":         action,
        "target":         target,
        "reason":         reason,
        "result":         result_msg,
        "timestamp":      timestamp,
        "firewall_state": {
            "blocked_ips":       FIREWALL_STATE["blocked_ips"],
            "blocked_ports":     FIREWALL_STATE["blocked_ports"],
            "rate_limited_ips":  FIREWALL_STATE["rate_limited_ips"],
            "isolated_hosts":    FIREWALL_STATE["isolated_hosts"],
            "network_stopped_count": FIREWALL_STATE["network_stopped_count"],
        }
    }

firewall_tool = FunctionTool(func=execute_containment)