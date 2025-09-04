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
# Static hostname → IP lookup dictionary
# =========================
STATIC_LOOKUP = {
    "aruba-tp-lrm": "10.17.10.186",
    "aruba-tp-edge-sw1-a": "10.17.10.190",
    "aruba-sw-sw1-a": "10.17.10.80",
    "aruba-sw-sw2-a": "10.17.10.81",
    "aruba-sw-sw1-b": "10.17.10.82",
    "aruba-sw-sw2-b": "10.17.10.83",
    "aruba-sw-lrm": "10.17.10.180",
}

# =========================
# Gateway router lookup for dynamic target determination
# =========================
GATEWAY_ROUTERS = {
    'aruba-sw-sw1-a.ucl.ac.uk': r'172.17.(52|53|54|55).\d+',
    'aruba-tp-edge-sw1-a.ucl.ac.uk': r'172.17.(56|57).\d+|172.22.29.\d+'
}

log_debug(f"✅ Loaded {len(STATIC_LOOKUP)} entries from static lookup dictionary")
log_debug(f"✅ Loaded {len(GATEWAY_ROUTERS)} gateway router patterns")

# =========================
# PathHop class
# =========================
class PathHop:
    def __init__(self, device_name, device_ip=None, local_interface=None, remote_interface=None):
        self.device_name = device_name
        self.device_ip = device_ip
        self.local_interface = local_interface  # Interface on current device connecting to next hop
        self.remote_interface = remote_interface  # Interface on remote device

    def __str__(self):
        if self.local_interface and self.remote_interface:
            return f"{self.device_name}[{self.local_interface}→{self.remote_interface}]"
        elif self.local_interface:
            return f"{self.device_name}[{self.local_interface}]"
        else:
            return self.device_name

    def __repr__(self):
        return self.__str__()

# =========================
# Helper functions
# =========================
def determine_target_device(source_ip: str) -> str:
    for gateway_device, ip_pattern in GATEWAY_ROUTERS.items():
        if re.match(ip_pattern, source_ip):
            target_hostname = gateway_device.replace('.ucl.ac.uk', '')
            log_debug(f"🎯 Source IP {source_ip} matched pattern {ip_pattern} → Target: {target_hostname}")
            return target_hostname
    log_debug(f"⚠️ No gateway pattern matched for source IP {source_ip}")
    return None

def hostname_to_ip(hostname: str) -> str:
    if hostname.lower() in STATIC_LOOKUP:
        return STATIC_LOOKUP[hostname.lower()]
    parts = hostname.split("-")
    if len(parts) >= 4:
        first_part = parts[0].lower()
        if (first_part.startswith("ce") or first_part.startswith("ae") or "ce" in first_part or "ae" in first_part):
            return "172." + ".".join(parts[1:4])
    return None

def is_aruba(ip: str) -> bool:
    return ip.startswith("172.22") or ip.startswith("10.17")

# =========================
# Parsing LLDP / CDP
# =========================
def parse_cisco_lldp_with_interfaces(output: str, visited: set) -> list:
    candidates = []
    log_debug("DEBUG: Parsing Cisco LLDP neighbors with interfaces...")

    pattern = re.compile(
        r'^(?P<device_id>\S+)\s+(?P<local_intf>Gi\d+/\d+/\d+|Fa\d+/\d+/\d+|Te\d+/\d+/\d+|Po\d+|Eth\d+/\d+|Ge\d+/\d+)\s+\d+\s+[\(\)BRWTCOPS,]+\s+(?P<remote_intf>\S+)',
        re.MULTILINE
    )

    for match in pattern.finditer(output):
        device_id = match.group("device_id").strip()
        local_intf = match.group("local_intf").strip()
        remote_intf = match.group("remote_intf").strip()
        device_id = re.split(r'\.u[a-z]+', device_id)[0].lower()
        if device_id in visited:
            continue
        if not (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
            continue
        candidates.append({
            'device_id': device_id,
            'local_interface': local_intf,
            'remote_interface': remote_intf
        })
        log_debug(f"DEBUG: LLDP candidate found - {device_id} via {local_intf}→{remote_intf}")

    return candidates

def parse_aruba_lldp_with_interfaces(output: str, visited: set) -> list:
    candidates = []
    log_debug("DEBUG: Parsing Aruba LLDP neighbors with interfaces...")
    lines = output.split('\n')
    in_table = False
    for line in lines:
        if 'LOCAL-PORT' in line and 'SYS-NAME' in line:
            in_table = True
            continue
        if in_table and '---' in line:
            continue
        if in_table and line.strip():
            parts = line.strip().split()
            if len(parts) >= 4:
                local_port = parts[0]
                port_id = parts[2]
                sys_name = parts[-1]
                device_id = sys_name.split('.')[0].lower()
                if device_id in visited:
                    continue
                if (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
                    candidates.append({
                        'device_id': device_id,
                        'local_interface': local_port,
                        'remote_interface': port_id
                    })
                    log_debug(f"DEBUG: Aruba LLDP candidate found - {device_id} via {local_port}→{port_id}")
    return candidates

def parse_cisco_cdp_with_interfaces(output: str, visited: set) -> list:
    candidates = []
    log_debug("DEBUG: Parsing Cisco CDP neighbors with interfaces...")
    entries = re.split(r'Device ID:', output)[1:]
    for entry in entries:
        lines = entry.strip().split('\n')
        if not lines:
            continue
        device_id = lines[0].strip().split('.')[0].lower()
        if device_id in visited:
            continue
        if not (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
            continue
        local_intf = None
        remote_intf = None
        for line in lines:
            line = line.strip()
            if line.startswith("Interface:"):
                interface_match = re.search(r'Interface:\s*(\S+),.*Port ID.*:\s*(\S+)', line)
                if interface_match:
                    local_intf = interface_match.group(1)
                    remote_intf = interface_match.group(2)
                    break
        if local_intf and remote_intf:
            candidates.append({
                'device_id': device_id,
                'local_interface': local_intf,
                'remote_interface': remote_intf
            })
            log_debug(f"DEBUG: CDP candidate found - {device_id} via {local_intf}→{remote_intf}")
    return candidates

# =========================
# Run commands
# =========================
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
# Trace Path with Last-Hop Fix
# =========================
def trace_path_with_interfaces(start_ip: str, target_name: str, creds: dict):
    visited_hostnames = set()
    queue = deque()
    start_hop = PathHop(start_ip, start_ip)
    queue.append((start_ip, None, [start_hop]))

    log_debug(f"➡️ Starting trace from {start_ip}")
    log_debug(f"🎯 Looking for target: {target_name}")

    while queue:
        current_ip, current_hostname, path = queue.popleft()
        log_debug(f"\n➡️ Tracing device: {current_ip} ({current_hostname})")
        log_debug(f"Current path: {' -> '.join([str(hop) for hop in path])}")

        if is_aruba(current_ip):
            output = run_command(current_ip, "show lldp neighbor-info", creds)
            candidates = parse_aruba_lldp_with_interfaces(output, visited_hostnames)
        else:
            output = run_command(current_ip, "show lldp neighbors", creds)
            candidates = parse_cisco_lldp_with_interfaces(output, visited_hostnames)
            if not candidates:
                log_debug("⚠️ No LLDP neighbors found, falling back to CDP...")
                cdp_output = run_command(current_ip, "show cdp neighbors detail", creds)
                candidates = parse_cisco_cdp_with_interfaces(cdp_output, visited_hostnames)

        log_debug(f"Candidates to explore: {[c['device_id'] for c in candidates]}")

        if not candidates:
            log_debug("⚠️ No candidates from this device.")
            continue

        for candidate in candidates:
            device_id = candidate['device_id']
            local_intf = candidate['local_interface']
            remote_intf = candidate['remote_interface']

            if target_name.lower() in device_id.lower():
                prev_hop = path[-1] if path else None
                last_local = remote_intf or (prev_hop.local_interface if prev_hop else None)
                target_hop = PathHop(
                    device_name=device_id,
                    device_ip=hostname_to_ip(device_id),
                    local_interface=last_local,
                    remote_interface=None
                )
                final_path = path + [target_hop]
                log_debug(f"✅ Target found: {device_id}")
                log_debug("✅ Trace completed successfully.")
                return final_path

            next_ip = hostname_to_ip(device_id)
            if not next_ip:
                log_debug(f"Could not resolve IP for {device_id}")
                continue
            if device_id in [hop.device_name for hop in path]:
                log_debug(f"Skipping {device_id} because already in current path")
                continue

            next_hop = PathHop(device_id, next_ip, local_intf, remote_intf)
            new_path = path + [next_hop]
            queue.append((next_ip, device_id, new_path))
            visited_hostnames.add(device_id)
            log_debug(f"Queued {device_id} ({next_ip}) with path: {' -> '.join([str(hop) for hop in new_path])}")

    log_debug("⚠️ Trace ended: target not found")
    return path

# =========================
# Dynamic trace wrapper
# =========================
def trace_path_dynamic_with_interfaces(start_ip: str, creds: dict, target_name: str = None):
    if target_name is None:
        target_name = determine_target_device(start_ip)
        if target_name is None:
            log_debug("❌ Could not determine target device from source IP")
            return [PathHop(start_ip, start_ip)]
    return trace_path_with_interfaces(start_ip, target_name, creds)

# =========================
# Extract trunk interfaces
# =========================
def get_trunk_interfaces_from_path(path: list) -> list:
    return [
        {
            'device_name': hop.device_name,
            'device_ip': hop.device_ip,
            'local_interface': hop.local_interface
        }
        for hop in path if hop.local_interface and hop.device_ip
    ]

# =========================
# Main usage
# =========================
if __name__ == "__main__":
    creds = {
        "cisco": {
            "username": os.environ.get("username"),
            "password": os.environ.get("password"),
            "secret": os.environ.get("secret"),
        },
        "aruba": {
            "username": os.environ.get("username"),
            "password": os.environ.get("passwordAD"),
        }
    }

    log_debug("=== Dynamic Network Trace with Interfaces ===")
    
    source_ip1 = "172.17.57.243"  # Example source IP
    path1 = trace_path_dynamic_with_interfaces(source_ip1, creds)
    log_debug(f"Dynamic Path 1 ({source_ip1}): " + " -> ".join([str(hop) for hop in path1]))
    
    trunk_interfaces = get_trunk_interfaces_from_path(path1)
    log_debug(f"Local interfaces to check for VLAN tags: {trunk_interfaces}")
    
    print("Trace complete. Debug log:", DEBUG_FILE)
