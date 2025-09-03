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
# Maps gateway devices to IP address patterns they serve
# =========================
GATEWAY_ROUTERS = {
    'aruba-sw-sw1-a.ucl.ac.uk': r'172\.17\.(52|53|54|55)\.\d+',
    'aruba-tp-edge-sw1-a.ucl.ac.uk': r'172\.17\.(56|57)\.\d+',
}

log_debug(f"✅ Loaded {len(STATIC_LOOKUP)} entries from static lookup dictionary")
log_debug(f"✅ Loaded {len(GATEWAY_ROUTERS)} gateway router patterns")

def determine_target_device(source_ip: str) -> str:
    """
    Dynamically determine the target device based on source IP address patterns.
    
    Args:
        source_ip: The source IP address to match against gateway patterns
        
    Returns:
        The target device hostname, or None if no match found
    """
    for gateway_device, ip_pattern in GATEWAY_ROUTERS.items():
        if re.match(ip_pattern, source_ip):
            # Remove the .ucl.ac.uk suffix and return just the hostname
            target_hostname = gateway_device.replace('.ucl.ac.uk', '')
            log_debug(f"🎯 Source IP {source_ip} matched pattern {ip_pattern} → Target: {target_hostname}")
            return target_hostname
    
    log_debug(f"⚠️ No gateway pattern matched for source IP {source_ip}")
    return None

def hostname_to_ip(hostname: str) -> str:
    # First try static lookup
    if hostname.lower() in STATIC_LOOKUP:
        return STATIC_LOOKUP[hostname.lower()]

    # Then try encoded names like ce-17-56-22 → 172.17.56.22
    # Also handle patterns like ce2960x-17-52-18, ce9300-17-52-100, etc.
    parts = hostname.split("-")
    if len(parts) >= 4:
        # Extract the first part and check if it starts with ce, ae, or contains these prefixes
        first_part = parts[0].lower()
        if (first_part.startswith("ce") or 
            first_part.startswith("ae") or
            "ce" in first_part or 
            "ae" in first_part):
            return "172." + ".".join(parts[1:4])

    return None

# =========================
# Helper Functions
# =========================
def is_aruba(ip: str) -> bool:
    return ip.startswith("172.22") or ip.startswith("10.17")

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
    log_debug("DEBUG: Parsing Aruba LLDP neighbors...")
    
    # Look for the table format in Aruba LLDP output
    lines = output.split('\n')
    in_table = False
    
    for line in lines:
        # Skip until we find the table header
        if 'LOCAL-PORT' in line and 'SYS-NAME' in line:
            in_table = True
            continue
        
        # Skip the separator line
        if in_table and '---' in line:
            continue
            
        # Process table rows
        if in_table and line.strip():
            # Split by whitespace and get the last column (SYS-NAME)
            parts = line.strip().split()
            if len(parts) >= 6:  # Ensure we have enough columns
                sys_name = parts[-1]  # Last column is SYS-NAME
                
                # Clean up the hostname (remove domain suffix if present)
                device_id = sys_name.split('.')[0].lower()
                
                if device_id in visited:
                    continue
                    
                # Check if it matches our device naming pattern
                if (device_id.startswith("ce") or 
                    device_id.startswith("ae") or 
                    device_id.startswith("aruba-")):
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
    log_debug(f"🎯 Looking for target: {target_name}")

    while queue:
        current_ip, current_hostname, path = queue.popleft()
        log_debug(f"\n➡️ Tracing device: {current_ip} ({current_hostname})")
        log_debug(f"Current path: {' -> '.join(path)}")

        # Pull neighbors
        if is_aruba(current_ip):
            output = run_command(current_ip, "show lldp neighbor-info", creds)
            print(output)
            candidates = parse_aruba_lldp(output, visited_hostnames)
            
            # Check if target is found in the current output
            if target_name.lower() in output.lower():
                log_debug(f"✅ Target {target_name} found in LLDP output!")
                final_path = path + [target_name]
                log_debug("✅ Trace completed successfully.")
                return final_path
                
        else:
            output = run_command(current_ip, "show lldp neighbors", creds)
            candidates = parse_cisco_lldp(output, visited_hostnames)
            
            # Check if target is found in the current output
            if target_name.lower() in output.lower():
                log_debug(f"✅ Target {target_name} found in LLDP output!")
                final_path = path + [target_name]
                log_debug("✅ Trace completed successfully.")
                return final_path
            
            if not candidates:
                log_debug("⚠️ No LLDP neighbors found, falling back to CDP...")
                cdp_output = run_command(current_ip, "show cdp neighbors detail", creds)
                
                # Check if target is found in CDP output
                if target_name.lower() in cdp_output.lower():
                    log_debug(f"✅ Target {target_name} found in CDP output!")
                    final_path = path + [target_name]
                    log_debug("✅ Trace completed successfully.")
                    return final_path
                
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
            print(f'candidates are - {candidates}')
            
            # Check if this candidate matches our target
            if target_name.lower() in c.lower():
                final_path = path + [c]
                log_debug(f"✅ Target found: {c}")
                log_debug("✅ Trace completed successfully.")
                return final_path
            
            next_ip = hostname_to_ip(c)
            print(f'next ip is - {next_ip}')
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

    log_debug("⚠️ Trace ended: target not found")
    return path

# =========================
# Enhanced trace function with dynamic target detection
# =========================
def trace_path_dynamic(start_ip: str, creds: dict, target_name: str = None):
    """
    Trace network path with dynamic target detection based on source IP.
    
    Args:
        start_ip: Starting IP address for the trace
        creds: Network device credentials
        target_name: Optional explicit target name (overrides dynamic detection)
        
    Returns:
        List representing the network path
    """
    # Determine target dynamically if not explicitly provided
    if target_name is None:
        target_name = determine_target_device(start_ip)
        if target_name is None:
            log_debug("❌ Could not determine target device from source IP")
            return [start_ip]
    
    return trace_path(start_ip, target_name, creds)

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
            "username": os.environ.get("username"),
            "password": os.environ.get("passwordAD"),
        }
    }

    log_debug("=== Dynamic Network Trace ===")
    
    # Example 1: Dynamic target detection based on source IP
    source_ip1 = "172.17.52.19"  # Should target aruba-sw-sw1-a
    path1 = trace_path_dynamic(source_ip1, creds)
    log_debug(f"Dynamic Path 1 ({source_ip1}): " + " -> ".join(path1))
    
    # Example 2: Another dynamic target detection
    #source_ip2 = "172.17.56.200"  # Should target aruba-tp-edge-sw1-a
    #path2 = trace_path_dynamic(source_ip2, creds)
    #log_debug(f"Dynamic Path 2 ({source_ip2}): " + " -> ".join(path2))
    
    # Example 3: Manual override (if you still want to specify target manually)
    # path3 = trace_path_dynamic("172.17.52.18", creds, target_name="aruba-sw-sw1-a")
    # log_debug(f"Manual Path: " + " -> ".join(path3))
    
    print("Trace complete. Debug log:", DEBUG_FILE)