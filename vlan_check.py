from netmiko import ConnectHandler
import re
import os
import logging
from typing import List, Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables
DEBUG_FILE = "vlan_check_debug.log"
SUPPRESS_RAW_OUTPUT = True  # Set to False if you need to see raw device outputs

# =========================
# Helper Functions
# =========================

def log_debug(message: str, level='info'):
    """Log messages with different levels."""
    if level == 'debug':
        logger.debug(message)
    else:
        logger.info(message)
    
    with open(DEBUG_FILE, 'a') as f:
        f.write(f"{message}\n")

def is_aruba(device_ip: str) -> bool:
    """Determine if a device is Aruba based on IP or other criteria."""
    # This is a simple implementation - you might want to enhance it
    aruba_ips = ['10.17.10.190']  # Add known Aruba IPs here
    return device_ip in aruba_ips

def run_command(device_ip: str, command: str, creds: dict) -> str:
    """
    Execute a command on a network device using Netmiko.
    
    Args:
        device_ip: IP address of the device
        command: Command to execute
        creds: Device credentials
    
    Returns:
        Command output as string
    """
    try:
        # Determine device type
        device_type = 'aruba_os' if is_aruba(device_ip) else 'cisco_ios'
        
        # Get appropriate credentials
        cred_key = 'aruba' if is_aruba(device_ip) else 'cisco'
        device_creds = creds.get(cred_key, {})
        
        # Set up connection parameters
        connection_params = {
            'device_type': device_type,
            'host': device_ip,
            'username': device_creds.get('username'),
            'password': device_creds.get('password'),
            'secret': device_creds.get('secret', ''),
            'timeout': 30,
            'verbose': False
        }
        
        # Connect and execute command
        with ConnectHandler(**connection_params) as net_connect:
            if device_creds.get('secret') and not is_aruba(device_ip):
                net_connect.enable()
            
            output = net_connect.send_command(command)
            return output
            
    except Exception as e:
        error_msg = f"Failed to execute command on {device_ip}: {str(e)}"
        log_debug(f"❌ {error_msg}", 'debug')
        raise Exception(error_msg)

# =========================
# PathHop Class
# =========================

class PathHop:
    """Class to represent a hop in the network path."""
    def __init__(self, device_name: str, device_ip: str, local_interface: str):
        self.device_name = device_name
        self.device_ip = device_ip
        self.local_interface = local_interface

# =========================
# VLAN Database and Trunk Checker
# =========================

def check_vlan_on_path(path: List[PathHop], vlan_id: int, creds: dict) -> dict:
    """
    Check if a VLAN exists in the database and on trunk uplinks throughout the network path.
    
    Args:
        path: List of PathHop objects representing the network path
        vlan_id: VLAN ID to check (integer)
        creds: Dictionary containing device credentials
    
    Returns:
        Dictionary with detailed VLAN status information for each device
    """
    vlan_status = {
        'vlan_id': vlan_id,
        'devices': [],
        'summary': {
            'total_devices': 0,
            'vlan_in_database': 0,
            'trunk_configured': 0,
            'vlan_on_trunk': 0,
            'issues_found': []
        }
    }
    
    log_debug(f"\n🔍 Checking VLAN {vlan_id} on network path...")
    
    for hop in path:
        if not hop.device_ip or not hop.local_interface:
            continue
            
        device_status = {
            'device_name': hop.device_name,
            'device_ip': hop.device_ip,
            'local_interface': hop.local_interface,
            'vlan_in_database': False,
            'interface_is_trunk': False,
            'vlan_on_trunk': False,
            'vlan_database_info': '',
            'trunk_info': '',
            'issues': []
        }
        
        log_debug(f"➡️ Checking {hop.device_name} ({hop.device_ip}) interface {hop.local_interface}")
        
        try:
            # Check VLAN in database
            vlan_db_status = check_vlan_database(hop.device_ip, vlan_id, creds)
            device_status['vlan_in_database'] = vlan_db_status['exists']
            device_status['vlan_database_info'] = vlan_db_status['info']
            
            if vlan_db_status['exists']:
                vlan_status['summary']['vlan_in_database'] += 1
                log_debug(f"✅ VLAN {vlan_id} found in database on {hop.device_name}", 'debug')
            else:
                device_status['issues'].append(f"VLAN {vlan_id} not in database")
                vlan_status['summary']['issues_found'].append(f"{hop.device_name}: VLAN not in database")
                log_debug(f"❌ VLAN {vlan_id} NOT found in database on {hop.device_name}", 'debug')
            
            # Check trunk configuration and VLAN on trunk
            trunk_status = check_trunk_interface(hop.device_ip, hop.local_interface, vlan_id, creds)
            device_status['interface_is_trunk'] = trunk_status['is_trunk']
            device_status['vlan_on_trunk'] = trunk_status['vlan_on_trunk']
            device_status['trunk_info'] = trunk_status['info']
            
            if trunk_status['is_trunk']:
                vlan_status['summary']['trunk_configured'] += 1
                log_debug(f"✅ Interface {hop.local_interface} is configured as trunk on {hop.device_name}", 'debug')
                
                if trunk_status['vlan_on_trunk']:
                    vlan_status['summary']['vlan_on_trunk'] += 1
                    log_debug(f"✅ VLAN {vlan_id} is allowed on trunk {hop.local_interface}", 'debug')
                else:
                    device_status['issues'].append(f"VLAN {vlan_id} not allowed on trunk {hop.local_interface}")
                    vlan_status['summary']['issues_found'].append(f"{hop.device_name}: VLAN not on trunk {hop.local_interface}")
                    log_debug(f"❌ VLAN {vlan_id} NOT allowed on trunk {hop.local_interface}", 'debug')
            else:
                device_status['issues'].append(f"Interface {hop.local_interface} not configured as trunk")
                vlan_status['summary']['issues_found'].append(f"{hop.device_name}: Interface {hop.local_interface} not trunk")
                log_debug(f"❌ Interface {hop.local_interface} is NOT configured as trunk on {hop.device_name}", 'debug')
                
        except Exception as e:
            error_msg = f"Error checking {hop.device_name}: {str(e)}"
            device_status['issues'].append(error_msg)
            vlan_status['summary']['issues_found'].append(error_msg)
            log_debug(f"❌ {error_msg}", 'debug')
        
        vlan_status['devices'].append(device_status)
        vlan_status['summary']['total_devices'] += 1
    
    # Generate summary report
    log_debug(f"\n📊 VLAN {vlan_id} Status Summary:")
    log_debug(f"Total devices checked: {vlan_status['summary']['total_devices']}")
    log_debug(f"VLAN in database: {vlan_status['summary']['vlan_in_database']}/{vlan_status['summary']['total_devices']}")
    log_debug(f"Trunk interfaces: {vlan_status['summary']['trunk_configured']}/{vlan_status['summary']['total_devices']}")
    log_debug(f"VLAN on trunks: {vlan_status['summary']['vlan_on_trunk']}/{vlan_status['summary']['trunk_configured']}")
    
    if vlan_status['summary']['issues_found']:
        log_debug(f"Issues found: {len(vlan_status['summary']['issues_found'])}")
        for issue in vlan_status['summary']['issues_found']:
            log_debug(f"  ⚠️ {issue}")
    else:
        log_debug("✅ No issues found - VLAN is properly configured throughout the path")
    
    return vlan_status


def check_vlan_database(device_ip: str, vlan_id: int, creds: dict) -> dict:
    """
    Check if a VLAN exists in the device's VLAN database.
    
    Args:
        device_ip: IP address of the device
        vlan_id: VLAN ID to check
        creds: Device credentials
    
    Returns:
        Dictionary with VLAN database status
    """
    result = {'exists': False, 'info': '', 'raw_output': ''}
    
    try:
        if is_aruba(device_ip):
            # Aruba AOS-CX command
            command = "show vlan"
            output = run_command(device_ip, command, creds)
            if not SUPPRESS_RAW_OUTPUT:
                result['raw_output'] = output
            
            # Parse Aruba VLAN output
            lines = output.split('\n')
            for line in lines:
                if line.strip().startswith(str(vlan_id)):
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == str(vlan_id):
                        vlan_name = parts[1] if len(parts) > 1 else "unnamed"
                        result['exists'] = True
                        result['info'] = f"VLAN {vlan_id} ({vlan_name}) exists"
                        break
        else:
            # Cisco IOS command
            command = f"show vlan id {vlan_id}"
            output = run_command(device_ip, command, creds)
            print(f'Command output for {device_ip}:\n{output}\n')  # Debug print
            if not SUPPRESS_RAW_OUTPUT:
                result['raw_output'] = output
            
            # Parse Cisco VLAN output
            if "VLAN Name" in output and not ("not found" in output.lower() or "invalid" in output.lower()):
                # Extract VLAN name
                lines = output.split('\n')
                for line in lines:
                    if line.strip().startswith(str(vlan_id)):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            vlan_name = parts[1]
                            result['exists'] = True
                            result['info'] = f"VLAN {vlan_id} ({vlan_name}) exists"
                            break
                        
    except Exception as e:
        result['info'] = f"Error checking VLAN database: {str(e)}"
        log_debug(f"❌ Error checking VLAN database on {device_ip}: {e}", 'debug')
    
    return result


def check_trunk_interface(device_ip: str, interface: str, vlan_id: int, creds: dict) -> dict:
    """
    Check if an interface is configured as a trunk and if a specific VLAN is allowed on it.
    
    Args:
        device_ip: IP address of the device
        interface: Interface name to check
        vlan_id: VLAN ID to check on the trunk
        creds: Device credentials
    
    Returns:
        Dictionary with trunk status information
    """
    result = {
        'is_trunk': False,
        'vlan_on_trunk': False,
        'info': '',
        'allowed_vlans': [],
        'raw_output': ''
    }
    
    try:
        if is_aruba(device_ip):
            # Aruba AOS-CX commands
            command = f"show interface {interface}"
            output = run_command(device_ip, command, creds)
            if not SUPPRESS_RAW_OUTPUT:
                result['raw_output'] = output
            
            # Check if interface is in trunk mode
            if "vlan_mode: trunk" in output.lower() or "mode: trunk" in output.lower():
                result['is_trunk'] = True
                result['info'] = f"Interface {interface} is configured as trunk"
                
                # Get VLAN information for the interface
                vlan_command = f"show vlan port {interface}"
                vlan_output = run_command(device_ip, vlan_command, creds)
                
                # Parse allowed VLANs (this may need adjustment based on actual Aruba output format)
                if str(vlan_id) in vlan_output:
                    result['vlan_on_trunk'] = True
                    result['info'] += f", VLAN {vlan_id} is allowed"
                else:
                    result['info'] += f", VLAN {vlan_id} is NOT allowed"
            else:
                result['info'] = f"Interface {interface} is NOT configured as trunk"
                
        else:
            # Cisco IOS commands
            command = f"show interfaces {interface} switchport"
            output = run_command(device_ip, command, creds)
            if not SUPPRESS_RAW_OUTPUT:
                result['raw_output'] = output
            
            # Check if interface is in trunk mode
            if "Administrative Mode: trunk" in output or "Operational Mode: trunk" in output:
                result['is_trunk'] = True
                result['info'] = f"Interface {interface} is configured as trunk"
                
                # Extract allowed VLANs
                allowed_vlans_match = re.search(r'Trunking VLANs Enabled: (.+)', output)
                if allowed_vlans_match:
                    allowed_vlans_str = allowed_vlans_match.group(1).strip()
                    
                    # Parse VLAN ranges and individual VLANs
                    if "ALL" in allowed_vlans_str.upper():
                        result['vlan_on_trunk'] = True
                        result['info'] += f", ALL VLANs allowed (including {vlan_id})"
                    else:
                        # Parse specific VLAN lists and ranges
                        vlan_allowed = parse_vlan_list(allowed_vlans_str, vlan_id)
                        result['vlan_on_trunk'] = vlan_allowed
                        if vlan_allowed:
                            result['info'] += f", VLAN {vlan_id} is allowed"
                        else:
                            result['info'] += f", VLAN {vlan_id} is NOT allowed"
                        result['allowed_vlans'] = allowed_vlans_str
                else:
                    result['info'] += ", could not determine allowed VLANs"
            else:
                result['info'] = f"Interface {interface} is NOT configured as trunk"
                
    except Exception as e:
        result['info'] = f"Error checking trunk interface: {str(e)}"
        log_debug(f"❌ Error checking trunk interface {interface} on {device_ip}: {e}", 'debug')
    
    return result


def parse_vlan_list(vlan_string: str, target_vlan: int) -> bool:
    """
    Parse a VLAN list string and check if target VLAN is included.
    Handles formats like: "1-10,20,30-40,50"
    
    Args:
        vlan_string: String containing VLAN list
        target_vlan: VLAN ID to search for
    
    Returns:
        Boolean indicating if target VLAN is in the list
    """
    try:
        vlan_parts = vlan_string.replace(' ', '').split(',')
        
        for part in vlan_parts:
            if '-' in part:
                # Handle range (e.g., "1-10")
                start, end = map(int, part.split('-'))
                if start <= target_vlan <= end:
                    return True
            else:
                # Handle individual VLAN
                if int(part) == target_vlan:
                    return True
        
        return False
    except (ValueError, AttributeError):
        log_debug(f"⚠️ Could not parse VLAN string: {vlan_string}", 'debug')
        return False


def generate_final_report(vlan_status: dict):
    """
    Generate a clean final report for each host in the path.
    
    Args:
        vlan_status: Dictionary with VLAN status information
    """
    vlan_id = vlan_status['vlan_id']
    
    print(f"\n{'='*60}")
    print(f"FINAL REPORT: VLAN {vlan_id} PATH ANALYSIS")
    print(f"{'='*60}")
    
    # Summary section
    summary = vlan_status['summary']
    print(f"\n📊 SUMMARY:")
    print(f"  Total devices checked: {summary['total_devices']}")
    print(f"  VLAN in database: {summary['vlan_in_database']}/{summary['total_devices']}")
    print(f"  Trunk interfaces: {summary['trunk_configured']}/{summary['total_devices']}")
    print(f"  VLAN on trunks: {summary['vlan_on_trunk']}/{summary['trunk_configured']}")
    
    if summary['issues_found']:
        print(f"  ⚠️  Issues found: {len(summary['issues_found'])}")
    else:
        print(f"  ✅ No issues found")
    
    # Detailed device reports
    print(f"\n📝 DETAILED DEVICE REPORTS:")
    for device in vlan_status['devices']:
        print(f"\n  Device: {device['device_name']} ({device['device_ip']})")
        print(f"    Interface: {device['local_interface']}")
        
        # VLAN database status
        vlan_db_status = "✅" if device['vlan_in_database'] else "❌"
        print(f"    VLAN in database: {vlan_db_status} {device['vlan_database_info']}")
        
        # Trunk status
        trunk_status = "✅" if device['interface_is_trunk'] else "❌"
        print(f"    Trunk configured: {trunk_status} {device['trunk_info']}")
        
        # VLAN on trunk status (only if trunk is configured)
        if device['interface_is_trunk']:
            vlan_trunk_status = "✅" if device['vlan_on_trunk'] else "❌"
            vlan_trunk_msg = "VLAN allowed on trunk" if device['vlan_on_trunk'] else "VLAN NOT allowed on trunk"
            print(f"    {vlan_trunk_msg}: {vlan_trunk_status}")
        
        # Issues
        if device['issues']:
            print(f"    ⚠️  Issues:")
            for issue in device['issues']:
                print(f"      - {issue}")
    
    # Overall status
    print(f"\n🎯 OVERALL STATUS:")
    if not summary['issues_found']:
        print("  ✅ SUCCESS: VLAN is properly configured throughout the path")
    else:
        print("  ❌ ISSUES DETECTED: VLAN configuration problems found")
        print(f"\n  Recommended actions:")
        for i, issue in enumerate(summary['issues_found'], 1):
            print(f"    {i}. {issue}")
    
    print(f"\n{'='*60}")
    print(f"Report complete. Detailed logs saved to: {DEBUG_FILE}")
    print(f"{'='*60}")


# =========================
# Main test execution
# =========================
if __name__ == "__main__":
    # Clear previous debug file
    with open(DEBUG_FILE, 'w') as f:
        f.write("")
    
    # Test path as provided
    #test_path = [
     #   PathHop('ce9300-17-57-242', '172.17.57.242', 'TenGigabitEthernet1/1/4'),
      #  PathHop('ce3650-17-57-241', '172.17.57.241', 'TenGigabitEthernet1/1/4'),
       # PathHop('ce3650-17-57-240', '172.17.57.240', 'TenGigabitEthernet1/1/4'),
        #PathHop('aruba-tp-edge-sw1-a', '10.17.10.190', '1/1/18')
    #]#

    test_path = [
        PathHop('172.22.29.199', '172.22.29.199', '1/1/51'),
        PathHop('ce3650-17-57-240', '172.17.57.240', 'TenGigabitEthernet1/1/4'),
        PathHop('aruba-tp-edge-sw1-a', '10.17.10.190', '1/1/18')
    ]
    
    # Credentials
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
    
    # Test VLAN (change this to the VLAN you want to test)
    test_vlan = 990
    
    log_debug("=== VLAN Check Test ===")
    log_debug(f"Path: {[f'{hop.device_name}[{hop.local_interface}]' for hop in test_path]}")
    log_debug(f"Testing VLAN: {test_vlan}")
    
    # Run the VLAN check
    result = check_vlan_on_path(test_path, test_vlan, creds)
    
    # Generate and display final report
    generate_final_report(result)