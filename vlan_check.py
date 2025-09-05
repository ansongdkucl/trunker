from netmiko import ConnectHandler
import re
import os
import logging
from typing import List, Set, Dict, Any, Optional
from dataclasses import dataclass

# =========================
# Logging Setup
# =========================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEBUG_FILE = "vlan_check_debug.log"
SUPPRESS_RAW_OUTPUT = True

# =========================
# Data Classes
# =========================
@dataclass
class PathHop:
    device_name: str
    device_ip: str
    local_interface: str

# =========================
# Helper Functions
# =========================

def log_debug(message: str, level='info'):
    """Log to console + file."""
    if level == 'debug':
        logger.debug(message)
    else:
        logger.info(message)
    with open(DEBUG_FILE, 'a') as f:
        f.write(f"{message}\n")

def is_aruba(device_ip: str) -> bool:
    """Detect Aruba CX devices by IP range or naming."""
    if device_ip.startswith("10.17.") or device_ip.startswith("172.22."):
        return True
    # hostname-based fallback if needed
    aruba_patterns = [r'aruba-', r'tp-edge-']
    for pattern in aruba_patterns:
        if re.search(pattern, device_ip, re.IGNORECASE):
            return True
    return False

def get_device_type(device_ip: str) -> str:
    """Determine device type based on IP."""
    return 'aruba_aoscx' if is_aruba(device_ip) else 'cisco_ios'

def get_connection_params(device_ip: str, creds: dict) -> Optional[Dict[str, Any]]:
    """Get connection parameters for a device."""
    device_type = get_device_type(device_ip)
    device_creds = creds.get("aruba" if device_type == 'aruba_aoscx' else "cisco", {})
    
    if not device_creds.get('username') or not device_creds.get('password'):
        log_debug(f"❌ Missing credentials for {device_ip}")
        return None
    
    params = {
        'device_type': device_type,
        'host': device_ip,
        'username': device_creds.get('username'),
        'password': device_creds.get('password'),
        'secret': device_creds.get('secret', ''),
        'timeout': 30,
        'verbose': False
    }
    return params

def get_connection(device_ip: str, creds: dict):
    """Establish connection to device."""
    params = get_connection_params(device_ip, creds)
    if not params:
        return None
    
    try:
        connection = ConnectHandler(**params)
        if params['device_type'] == 'cisco_ios' and params.get('secret'):
            connection.enable()
        return connection
    except Exception as e:
        log_debug(f"❌ Failed to connect to {device_ip}: {str(e)}")
        return None

def run_command(device_ip: str, command: str, creds: dict) -> str:
    """Run a command on a network device using Netmiko."""
    connection = get_connection(device_ip, creds)
    if not connection:
        raise Exception(f"Failed to connect to {device_ip}")
    
    try:
        return connection.send_command(command)
    except Exception as e:
        msg = f"❌ Failed to run '{command}' on {device_ip}: {str(e)}"
        log_debug(msg)
        raise Exception(msg)
    finally:
        connection.disconnect()

def test_device_connectivity(device_ip: str, creds: dict) -> bool:
    """Test login with creds and run 'show version'."""
    connection = get_connection(device_ip, creds)
    if not connection:
        return False
    
    try:
        connection.send_command("show version", delay_factor=2)
        log_debug(f"✅ Connected to {device_ip}")
        return True
    except Exception as e:
        log_debug(f"❌ Failed to test connectivity to {device_ip}: {str(e)}")
        return False
    finally:
        connection.disconnect()

# =========================
# VLAN + Trunk Parsing
# =========================

def parse_vlan_list(vlan_str: str) -> Set[int]:
    """Expand Cisco VLAN list string (e.g. '2,5,10,20-22') into a set of ints."""
    vlans = set()
    for part in vlan_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            try:
                vlans.update(range(int(start), int(end) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            vlans.add(int(part))
    return vlans

def get_vlan_database(ip: str, creds: dict) -> Set[int]:
    """Retrieve VLAN database (all configured VLANs) for Cisco or Aruba."""
    connection = get_connection(ip, creds)
    if not connection:
        return set()

    try:
        device_type = get_device_type(ip)
        vlans = set()
        
        if device_type == "cisco_ios":
            output = connection.send_command("show vlan brief")
            for line in output.splitlines():
                match = re.match(r"^\s*(\d+)\s+\S+\s+(active|act/unsup)", line, re.IGNORECASE)
                if match:
                    vlans.add(int(match.group(1)))
        
        elif device_type == "aruba_aoscx":
            output = connection.send_command("show vlan")
            for line in output.splitlines():
                match = re.match(r"^\s*(\d+)\s", line)
                if match:
                    vlans.add(int(match.group(1)))
        
        return vlans

    except Exception as e:
        log_debug(f"❌ Failed to get VLAN database from {ip}: {str(e)}")
        return set()
    finally:
        connection.disconnect()

def get_trunk_vlans(ip: str, interface: str, creds: dict) -> Set[int]:
    """Return VLANs allowed on trunk for Cisco or Aruba devices."""
    connection = get_connection(ip, creds)
    if not connection:
        return set()

    try:
        device_type = get_device_type(ip)
        
        if device_type == "cisco_ios":
            # Use the general trunk command
            output = connection.send_command("show interfaces trunk")
            log_debug(f"Raw trunk output for {ip}:\n{output}", 'debug')
            
            vlans_allowed = set()
            lines = output.splitlines()
            
            # Convert interface name to short format (e.g., "TenGigabitEthernet1/1/4" -> "Te1/1/4")
            interface_short = interface.replace("TenGigabitEthernet", "Te").replace("GigabitEthernet", "Gi").replace("FastEthernet", "Fa")
            
            # Look for the "Vlans allowed on trunk" section
            for i, line in enumerate(lines):
                if "vlans allowed on trunk" in line.lower():
                    # Check the next few lines for our interface
                    for j in range(i + 1, min(i + 10, len(lines))):
                        next_line = lines[j].strip()
                        if next_line and not next_line.startswith("Port"):
                            # Check if this line starts with our interface name (short format)
                            if next_line.lower().startswith(interface_short.lower()):
                                # Extract the VLAN list (everything after the interface name)
                                vlan_part = next_line[len(interface_short):].strip()
                                # The VLAN list should be the first element
                                vlan_str = vlan_part.split()[0] if vlan_part.split() else ""
                                log_debug(f"DEBUG: Found VLAN string for {interface_short}: '{vlan_str}'", 'debug')
                                vlans_allowed.update(parse_vlan_list(vlan_str))
                                break
                    break
            
            return vlans_allowed

        elif device_type == "aruba_aoscx":
            output = connection.send_command(f"show vlan port {interface}")
            vlans = set()
            for line in output.splitlines():
                match = re.match(r"^\s*(\d+)\s+\S+", line)
                if match:
                    vlans.add(int(match.group(1)))
            return vlans

    except Exception as e:
        log_debug(f"❌ Failed to get trunk VLANs from {ip} interface {interface}: {str(e)}")
        return set()
    finally:
        connection.disconnect()

# =========================
# VLAN Path Consistency Check
# =========================

def check_vlan_consistency(path: List[PathHop], vlan: int, creds: dict):
    """Check if VLAN is consistently present/allowed along a path."""
    results = []
    consistent = True

    for hop in path:
        vlans_db = get_vlan_database(hop.device_ip, creds)
        vlans_trunk = get_trunk_vlans(hop.device_ip, hop.local_interface, creds)

        in_db = vlan in vlans_db
        on_trunk = vlan in vlans_trunk

        hop_result = {
            "device": hop.device_name,
            "ip": hop.device_ip,
            "interface": hop.local_interface,
            "in_db": in_db,
            "on_trunk": on_trunk,
            "vlans_db": vlans_db,
            "vlans_trunk": vlans_trunk
        }
        results.append(hop_result)

        if not (in_db and on_trunk):
            consistent = False

    return consistent, results

def print_vlan_report(vlan: int, results: List[dict], consistent: bool):
    """Print a readable VLAN report."""
    print(f"\n=== VLAN {vlan} Consistency Report ===")
    for r in results:
        db_status = "✅" if r["in_db"] else "❌"
        trunk_status = "✅" if r["on_trunk"] else "❌"
        print(f"{r['device']} ({r['ip']}): DB={db_status}, Trunk[{r['interface']}]={trunk_status}")
        
        # Show available VLANs for debugging when there are issues
        if not r["in_db"]:
            print(f"  Available VLANs in DB: {sorted(r['vlans_db'])}")
        if not r["on_trunk"]:
            print(f"  VLANs allowed on trunk: {sorted(r['vlans_trunk'])}")

    if consistent:
        print(f"\n✅ VLAN {vlan} is consistently present across the entire path.")
    else:
        print(f"\n❌ VLAN {vlan} is NOT consistent along the path.")

# =========================
# Main Execution
# =========================
if __name__ == "__main__":
    # Reset debug log
    with open(DEBUG_FILE, 'w') as f:
        f.write("")

    # Example path
    #test_path = [
      #  PathHop('172.22.29.199', '172.22.29.199', '1/1/51'),
       # PathHop('ce3650-17-57-240', '172.17.57.240', 'Te1/1/4'),
       # PathHop('aruba-tp-edge-sw1-a', '10.17.10.86', '1/1/18')
    #]

    test_path = [
         PathHop('ce9300-17-57-243','172.17.57.243','Te1/0/2'),
        PathHop('ce9300-17-57-242','172.17.57.242','Te1/1/3'),
        PathHop('ce3650-17-57-241','172.17.57.241','Te1/1/4'),
        PathHop('ce3650-17-57-240','172.17.57.240', 'Te1/1/4'),
        PathHop('aruba-tp-edge-sw1-a','10.17.10.86','1/1/18')
]

    creds = {
        "cisco": {
            "username": os.environ.get("NET_USERNAME") or os.environ.get("username"),
            "password": os.environ.get("NET_PASSWORD") or os.environ.get("password"),
            "secret": os.environ.get("NET_SECRET") or os.environ.get("secret"),
        },
        "aruba": {
            "username": os.environ.get("NET_USERNAME") or os.environ.get("username"),
            "password": os.environ.get("NET_PASSWORD_AD") or os.environ.get("passwordAD"),
        }
    }

    log_debug("=== CREDS DEBUG ===")
    log_debug(f"Cisco user: {creds['cisco']['username']}")
    log_debug(f"Aruba user: {creds['aruba']['username']}")
    log_debug(f"Aruba pw set: {'Yes' if creds['aruba']['password'] else 'No'}")

    log_debug("\n=== CONNECTIVITY TEST ===")
    connectivity_results = {}
    for hop in test_path:
        connectivity_results[hop.device_ip] = test_device_connectivity(hop.device_ip, creds)

    if not all(connectivity_results.values()):
        print("❌ Connectivity issues detected:")
        for ip, ok in connectivity_results.items():
            print(f"  {ip}: {'✅ Reachable' if ok else '❌ NOT Reachable'}")
        print("Fix issues before running VLAN check.")
    else:
        print("✅ All devices reachable — running VLAN consistency check...")
        vlan_to_check = 990  # <-- set VLAN you want to check
        consistent, results = check_vlan_consistency(test_path, vlan_to_check, creds)
        print_vlan_report(vlan_to_check, results, consistent)