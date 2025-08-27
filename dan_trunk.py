from netmiko import ConnectHandler
import re
import os
from collections import deque
import datetime

# =========================
# Debug Logging
# =========================
DEBUG_FILE = f"trace_debug_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log_debug(msg):
    print(msg)
    with open(DEBUG_FILE, "a") as f:
        f.write(msg + "\n")

# =========================
# Helper Functions
# =========================
def hostname_to_ip(hostname: str) -> str:
    parts = hostname.split("-")
    if len(parts) < 4:
        return None
    return "172." + ".".join(parts[1:4])

def is_aruba(ip: str) -> bool:
    return ip.startswith("172.22")

def parse_cisco_lldp(output: str, visited: set) -> list:
    candidates = []
    log_debug("DEBUG: Parsing Cisco LLDP neighbors...")
    pattern = re.compile(
        r'^(?P<device_id>.+?)(?P<local_intf>Gi|Fa|Te|Po|Eth|Ge)\S*\s+(\d+)\s+[\(\)BRWTCOPS,]+\s+\S+',
        re.MULTILINE
    )
    for match in pattern.finditer(output):
        device_id = match.group("device_id").strip()
        device_id = re.split(r'\.u[a-z]+', device_id)[0].lower()
        if device_id in visited:
            continue
        if not (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
            continue
        candidates.append(device_id)
        log_debug(f"DEBUG: LLDP candidate found - {device_id}")
    return candidates

def parse_aruba_lldp(output: str, visited: set) -> list:
    candidates = []
    pattern = re.compile(r'Neighbor System-Name\s+:\s+(\S+)')
    for match in pattern.finditer(output):
        device_id = match.group(1).split(".")[0].lower()
        if device_id in visited:
            continue
        if device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-"):
            candidates.append(device_id)
            log_debug(f"DEBUG: Aruba LLDP candidate found - {device_id}")
    return candidates

def run_command(ip: str, command: str, creds: dict) -> str:
    if is_aruba(ip):
        device = {
            "device_type": "aruba_aoscx",
            "host": ip,
            "username": creds["aruba"]["username"],
            "password": creds["aruba"]["password"],
        }
    else:
        device = {
            "device_type": "cisco_ios",
            "host": ip,
            "username": creds["cisco"]["username"],
            "password": creds["cisco"]["password"],
            "secret": creds["cisco"]["secret"],
        }

    try:
        conn = ConnectHandler(**device)
        if not is_aruba(ip):
            conn.enable()
        output = conn.send_command(command)
        conn.disconnect()
        return output
    except Exception as e:
        log_debug(f"❌ Connection to {ip} failed: {e}")
        return ""

# =========================
# Trace BFS with backtracking and CDP fallback
# =========================
def trace_path(start_ip: str, target_name: str, creds: dict):
    visited_hostnames = set()
    queue = deque()
    queue.append((start_ip, None, [start_ip]))  # (current_ip, hostname, path)

    log_debug(f"➡️ Starting trace from {start_ip}")

    while queue:
        current_ip, current_hostname, path = queue.popleft()
        log_debug(f"\n➡️ Tracing device: {current_ip} ({current_hostname})")
        log_debug(f"Current path: {' -> '.join(path)}")

        # Pull neighbors
        if is_aruba(current_ip):
            output = run_command(current_ip, "show lldp neighbor-info", creds)
            candidates = parse_aruba_lldp(output, visited_hostnames)
        else:
            output = run_command(current_ip, "show lldp neighbors", creds)
            candidates = parse_cisco_lldp(output, visited_hostnames)
            if not candidates:
                log_debug("⚠️ No LLDP neighbors found, falling back to CDP...")
                cdp_output = run_command(current_ip, "show cdp neighbors detail", creds)
                candidates = []
                for line in cdp_output.splitlines():
                    if line.strip().startswith("Device ID:"):
                        device_id = line.split("Device ID:")[1].strip().split(".")[0].lower()
                        if device_id not in visited_hostnames and (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
                            candidates.append(device_id)
                            log_debug(f"DEBUG: CDP candidate found - {device_id}")

        log_debug(f"Candidates to explore: {candidates}")

        if not candidates:
            log_debug("⚠️ No candidates from this device.")
            continue

        for c in candidates:
            next_ip = hostname_to_ip(c)
            if not next_ip:
                log_debug(f"Could not resolve IP for {c}")
                continue
            if c in path:
                log_debug(f"Skipping {c} because already in current path")
                continue

            new_path = path + [c]
            queue.append((next_ip, c, new_path))
            visited_hostnames.add(c)
            log_debug(f"Queued {c} ({next_ip}) with path: {' -> '.join(new_path)}")

            if target_name in c:
                log_debug("✅ Trace completed successfully.")
                return new_path

    log_debug("⚠️ Trace ended: target not found")
    return path

# =========================
# Example Usage
# =========================
if __name__ == "__main__":
    creds = {
        "cisco": {
            "username": os.environ.get("username"),
            "password": os.environ.get("password"),
            "secret": os.environ.get("secret"),
        },
        "aruba": {
            "username": os.environ.get("user"),
            "password": os.environ.get("passwordAD"),
        }
    }

    log_debug("=== Cisco to Aruba Trace ===")
    path1 = trace_path("172.17.56.4", "aruba-tp-edge-sw1-a", creds)
    log_debug("Final Path: " + " -> ".join(path1))
    print("Trace complete. Debug log:", DEBUG_FILE)
