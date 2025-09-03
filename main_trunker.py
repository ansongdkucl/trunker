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
    'aruba-sw-sw1-a.ucl.ac.uk': r'172.17.(52|53|54|55).\d+',
    'aruba-tp-edge-sw1-a.ucl.ac.uk': r'172.17.(56|57).\d+|172.22.29.\d+'
}

log_debug(f"✅ Loaded {len(STATIC_LOOKUP)} entries from static lookup dictionary")
log_debug(f"✅ Loaded {len(GATEWAY_ROUTERS)} gateway router patterns")

# =========================
# Data Structure for Path with Interfaces
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

def determine_target_device(source_ip: str) -> str:
    """
    Dynamically determine the target device based on source IP address patterns.
    """
    for gateway_device, ip_pattern in GATEWAY_ROUTERS.items():
        if re.match(ip_pattern, source_ip):
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
    parts = hostname.split("-")
    if len(parts) >= 4:
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

def parse_cisco_lldp_with_interfaces(output: str, visited: set) -> list:
    """Parse Cisco LLDP neighbors and extract interface information"""
    candidates = []
    log_debug("DEBUG: Parsing Cisco LLDP neighbors with interfaces...")
    
    # Pattern to match LLDP neighbor entries with interfaces
    # Example: "ce-17-52-18              Gi1/0/1        120           BR            Gi0/0/1"
    pattern = re.compile(
        r'^(?P<device_id>\S+)\s+(?P<local_intf>Gi\d+/\d+/\d+|Fa\d+/\d+/\d+|Te\d+/\d+/\d+|Po\d+|Eth\d+/\d+|Ge\d+/\d+)\s+\d+\s+[\(\)BRWTCOPS,]+\s+(?P<remote_intf>\S+)',
        re.MULTILINE
    )
    
    for match in pattern.finditer(output):
        device_id = match.group("device_id").strip()
        local_intf = match.group("local_intf").strip()
        remote_intf = match.group("remote_intf").strip()
        
        # Clean device ID
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
    """Parse Aruba LLDP neighbors and extract interface information"""
    candidates = []
    log_debug("DEBUG: Parsing Aruba LLDP neighbors with interfaces...")
    
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
            # Split by whitespace - typical format:
            # LOCAL-PORT  CHASSIS-ID         PORT-ID            SYS-NAME
            # 1/1/1       aa:bb:cc:dd:ee:ff  1/1/24             ce-17-52-18
            parts = line.strip().split()
            if len(parts) >= 4:
                local_port = parts[0]
                port_id = parts[2]  # This is the remote interface
                sys_name = parts[-1]  # Last column is SYS-NAME
                
                # Clean up the hostname
                device_id = sys_name.split('.')[0].lower()
                
                if device_id in visited:
                    continue
                    
                # Check if it matches our device naming pattern
                if (device_id.startswith("ce") or 
                    device_id.startswith("ae") or 
                    device_id.startswith("aruba-")):
                    
                    candidates.append({
                        'device_id': device_id,
                        'local_interface': local_port,
                        'remote_interface': port_id
                    })
                    log_debug(f"DEBUG: Aruba LLDP candidate found - {device_id} via {local_port}→{port_id}")
    
    return candidates

def parse_cisco_cdp_with_interfaces(output: str, visited: set) -> list:
    """Parse Cisco CDP neighbors and extract interface information"""
    candidates = []
    log_debug("DEBUG: Parsing Cisco CDP neighbors with interfaces...")
    
    # Split CDP output by entries (each entry starts with "Device ID:")
    entries = re.split(r'Device ID:', output)[1:]  # Skip first empty split
    
    for entry in entries:
        lines = entry.strip().split('\n')
        if not lines:
            continue
            
        # First line contains device ID
        device_id = lines[0].strip().split('.')[0].lower()
        
        if device_id in visited:
            continue
        if not (device_id.startswith("ce") or device_id.startswith("ae") or device_id.startswith("aruba-")):
            continue
        
        local_intf = None
        remote_intf = None
        
        # Look for interface information in the entry
        for line in lines:
            line = line.strip()
            if line.startswith("Interface:"):
                # Format: "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet0/0/1"
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
# Enhanced Trace BFS with Interface Information
# =========================
def trace_path_with_interfaces(start_ip: str, target_name: str, creds: dict):
    visited_hostnames = set()
    queue = deque()
    
    # Initialize with starting hop
    start_hop = PathHop(start_ip, start_ip)
    queue.append((start_ip, None, [start_hop]))  # (current_ip, hostname, path)

    log_debug(f"➡️ Starting trace from {start_ip}")
    log_debug(f"🎯 Looking for target: {target_name}")

    while queue:
        current_ip, current_hostname, path = queue.popleft()
        log_debug(f"\n➡️ Tracing device: {current_ip} ({current_hostname})")
        log_debug(f"Current path: {' -> '.join([str(hop) for hop in path])}")

        # Pull neighbors with interface information
        if is_aruba(current_ip):
            output = run_command(current_ip, "show lldp neighbor-info", creds)
            candidates = parse_aruba_lldp_with_interfaces(output, visited_hostnames)
            
            # Check if target is found in the current output
            if target_name.lower() in output.lower():
                log_debug(f"✅ Target {target_name} found in LLDP output!")
                # Try to find interface info for the target
                target_hop = PathHop(target_name)
                for candidate in candidates:
                    if target_name.lower() in candidate['device_id'].lower():
                        target_hop = PathHop(
                            target_name, 
                            None, 
                            candidate['local_interface'], 
                            candidate['remote_interface']
                        )
                        break
                final_path = path + [target_hop]
                log_debug("✅ Trace completed successfully.")
                return final_path
                
        else:
            output = run_command(current_ip, "show lldp neighbors", creds)
            candidates = parse_cisco_lldp_with_interfaces(output, visited_hostnames)
            
            # Check if target is found in the current output
            if target_name.lower() in output.lower():
                log_debug(f"✅ Target {target_name} found in LLDP output!")
                # Try to find interface info for the target
                target_hop = PathHop(target_name)
                for candidate in candidates:
                    if target_name.lower() in candidate['device_id'].lower():
                        target_hop = PathHop(
                            target_name, 
                            None, 
                            candidate['local_interface'], 
                            candidate['remote_interface']
                        )
                        break
                final_path = path + [target_hop]
                log_debug("✅ Trace completed successfully.")
                return final_path
            
            if not candidates:
                log_debug("⚠️ No LLDP neighbors found, falling back to CDP...")
                cdp_output = run_command(current_ip, "show cdp neighbors detail", creds)
                
                # Check if target is found in CDP output
                if target_name.lower() in cdp_output.lower():
                    log_debug(f"✅ Target {target_name} found in CDP output!")
                    candidates = parse_cisco_cdp_with_interfaces(cdp_output, visited_hostnames)
                    target_hop = PathHop(target_name)
                    for candidate in candidates:
                        if target_name.lower() in candidate['device_id'].lower():
                            target_hop = PathHop(
                                target_name, 
                                None, 
                                candidate['local_interface'], 
                                candidate['remote_interface']
                            )
                            break
                    final_path = path + [target_hop]
                    log_debug("✅ Trace completed successfully.")
                    return final_path
                
                candidates = parse_cisco_cdp_with_interfaces(cdp_output, visited_hostnames)

        log_debug(f"Candidates to explore: {[c['device_id'] for c in candidates]}")

        if not candidates:
            log_debug("⚠️ No candidates from this device.")
            continue

        for candidate in candidates:
            device_id = candidate['device_id']
            local_intf = candidate['local_interface']
            remote_intf = candidate['remote_interface']
            
            print(f'Candidate: {device_id} via {local_intf}→{remote_intf}')
            
            # Check if this candidate matches our target
            if target_name.lower() in device_id.lower():
                target_hop = PathHop(device_id, None, local_intf, remote_intf)
                final_path = path + [target_hop]
                log_debug(f"✅ Target found: {device_id}")
                log_debug("✅ Trace completed successfully.")
                return final_path
            
            next_ip = hostname_to_ip(device_id)
            print(f'Next IP for {device_id}: {next_ip}')
            
            if not next_ip:
                log_debug(f"Could not resolve IP for {device_id}")
                continue
            if device_id in [hop.device_name for hop in path]:
                log_debug(f"Skipping {device_id} because already in current path")
                continue

            # Create new hop with interface information
            next_hop = PathHop(device_id, next_ip, local_intf, remote_intf)
            new_path = path + [next_hop]
            
            queue.append((next_ip, device_id, new_path))
            visited_hostnames.add(device_id)
            log_debug(f"Queued {device_id} ({next_ip}) with path: {' -> '.join([str(hop) for hop in new_path])}")

    log_debug("⚠️ Trace ended: target not found")
    return path

# =========================
# Enhanced trace function with dynamic target detection and interfaces
# =========================
def trace_path_dynamic_with_interfaces(start_ip: str, creds: dict, target_name: str = None):
    """
    Trace network path with dynamic target detection and interface information.
    """
    # Determine target dynamically if not explicitly provided
    if target_name is None:
        target_name = determine_target_device(start_ip)
        if target_name is None:
            log_debug("❌ Could not determine target device from source IP")
            return [PathHop(start_ip, start_ip)]
    
    return trace_path_with_interfaces(start_ip, target_name, creds)

def get_trunk_interfaces_from_path(path: list) -> list:
    """
    Extract trunk interface information from the traced path.
    Returns list of tuples: (device_name, device_ip, local_interface)
    """
    trunk_interfaces = []
    
    for hop in path:
        if hop.local_interface and hop.device_ip:
            trunk_interfaces.append({
                'device_name': hop.device_name,
                'device_ip': hop.device_ip,
                'local_interface': hop.local_interface,
                'remote_interface': hop.remote_interface
            })
    
    return trunk_interfaces

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

    log_debug("=== Dynamic Network Trace with Interfaces ===")
    
    # Example 1: Dynamic target detection with interface information
    source_ip1 = "172.17.57.243"  # Should target aruba-sw-sw1-a
    path1 = trace_path_dynamic_with_interfaces(source_ip1, creds)
    log_debug(f"Dynamic Path 1 ({source_ip1}): " + " -> ".join([str(hop) for hop in path1]))
    
    # Extract trunk interfaces for VLAN checking
    trunk_interfaces = get_trunk_interfaces_from_path(path1)
    log_debug(f"Trunk interfaces to check: {trunk_interfaces}")
    
    print("Trace complete. Debug log:", DEBUG_FILE)