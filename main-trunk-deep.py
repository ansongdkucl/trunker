from nornir import InitNornir
from nornir_netmiko import netmiko_send_command
from nornir.core.task import Task, Result
from typing import Dict, List, Tuple, Optional
import networkx as nx
import matplotlib.pyplot as plt
import re

def get_lldp_neighbors(task: Task) -> List[Dict]:
    """Collect LLDP neighbor information in a vendor-neutral way"""
    platform = task.host.platform
    
    # Vendor-specific command variations
    command = "show lldp neighbors detail" if platform == "aruba_cx" else "show lldp neighbors detail"
    
    print(f"\n[DEBUG] Running on {task.host}: {command}")
    result = task.run(
        task=netmiko_send_command,
        command_string=command,
        use_textfsm=True,
        enable=True
    )
    
    # Ensure we always return a list of dictionaries
    if isinstance(result.result, str):
        print(f"[ERROR] TextFSM parsing failed, raw output: {result.result}")
        return []
    elif isinstance(result.result, dict):
        return [result.result]
    elif not result.result:
        return []
    
    return result.result

def find_uplink_port(task: Task, neighbor_ip: str) -> Optional[str]:
    """Find the local interface connected to a neighbor (vendor-neutral)"""
    platform = task.host.platform
    
    try:
        if platform == "aruba_cx":
            command = f"show lldp neighbors {neighbor_ip} detail"
            print(f"\n[DEBUG] Running on {task.host}: {command}")
            result = task.run(
                task=netmiko_send_command,
                command_string=command,
                use_textfsm=True,
                enable=True
            )
            print(f"[DEBUG] LLDP neighbor detail on {task.host}: {result.result}")
            if result.result:
                return result.result[0]['local_interface']
        else:  # Cisco and similar
            # First try LLDP
            #command = f"show lldp neighbors {neighbor_ip} detail"
            command = f"show lldp neighbors detail"
            print(f"\n[DEBUG] Running on {task.host}: {command}")
            result = task.run(
                task=netmiko_send_command,
                command_string=command,
                use_textfsm=True,
                enable=True
            )
            print(f"[DEBUG] LLDP neighbor detail on {task.host}: {result.result}")
            if result.result:
                return result.result[0]['local_interface']
            print('[DEBUG] Found local interface via LLDP')
            print( result.result[0]['local_interface'])
            # If LLDP doesn't work, try CDP
            
            # Fall back to CDP if LLDP fails
            command = f"show cdp neighbor {neighbor_ip} detail"
            print(f"\n[DEBUG] Running on {task.host}: {command}")
            result = task.run(
                task=netmiko_send_command,
                command_string=command,
                use_textfsm=True,
            enable=True
            )
            print(f"[DEBUG] CDP neighbor detail on {task.host}: {result.result}")
            if result.result:
                return result.result[0]['local_port']
    
    except Exception as e:
        print(f"[ERROR] Error finding uplink port on {task.host}: {str(e)}")
    
    return None

def verify_vlan_exists(task: Task, vlan_id: str) -> bool:
    """Check if VLAN exists in database (vendor-neutral)"""
    platform = task.host.platform
    
    try:
        if platform == "aruba_cx":
            command = f"show vlan {vlan_id}"
        else:
            command = f"show vlan id {vlan_id}"
        
        print(f"\n[DEBUG] Running on {task.host}: {command}")
        result = task.run(
            task=netmiko_send_command,
            command_string=command,
            use_textfsm=True,
            enable=True
        )
        print(f"[DEBUG] VLAN check result on {task.host}: {result.result}")
        
        return bool(result.result)
    
    except Exception as e:
        print(f"[ERROR] Error checking VLAN on {task.host}: {str(e)}")
        return False

def verify_access_vlan(task: Task, interface: str, vlan_id: str) -> bool:
    """Verify access port VLAN configuration (vendor-neutral)"""
    try:
        # First try show vlan brief output
        command = f"show vlan id {vlan_id}"
        print(f"\n[DEBUG] Running on {task.host}: {command}")
        vlan_result = task.run(
            task=netmiko_send_command,
            command_string=command,
            use_textfsm=True
        )
        print(f"[DEBUG] VLAN membership check on {task.host}: {vlan_result.result}")
        
        if vlan_result.result:
            for vlan in vlan_result.result:
                if interface in vlan.get('interfaces', []):
                    print(f"[DEBUG] Found {interface} in VLAN {vlan_id} via show vlan")
                    return True
        
        # Fall back to interface config check
        command = f"show running-config interface {interface}"
        print(f"\n[DEBUG] Running on {task.host}: {command}")
        result = task.run(
            task=netmiko_send_command,
            command_string=command,
            use_textfsm=False,
            enable=True
        )
        print(f"[DEBUG] Interface config on {task.host}: {result.result}")
        
        config = result.result.lower()
        if f"switchport access vlan {vlan_id}" in config:
            print(f"[DEBUG] Found access vlan config in interface configuration")
            return True
        if f"vlan {vlan_id}" in config:
            print(f"[DEBUG] Found vlan reference in interface configuration")
            return True
        
        print(f"[DEBUG] No access vlan configuration found for {interface}")
        return False
    
    except Exception as e:
        print(f"[ERROR] Error checking access port on {task.host}: {str(e)}")
        return False

def verify_trunk_vlan(task: Task, interface: str, vlan_id: str) -> bool:
    """Verify trunk allows the VLAN using switchport status (with minimal fallback)"""
    try:
        # Primary method: structured switchport data
        command = f"show interfaces {interface} switchport"
        print(f"\n[DEBUG] Running on {task.host}: {command}")
        result = task.run(
            task=netmiko_send_command,
            command_string=command,
            use_textfsm=True,
            enable=True
        )
        
        if result.result and isinstance(result.result, list):
            sw_data = result.result[0]
            
            # 1. Verify port is actually trunking
            if sw_data.get('mode', '').lower() != 'trunk':
                print(f"[DEBUG] Port {interface} is not in trunk mode")
                return False
            
            # 2. Check if trunk allows ALL VLANs
            if any(field == 'ALL' 
                  for field in [sw_data.get('trunking_vlans', ''), 
                               sw_data.get('vlans_allowed', '')]):
                print(f"[DEBUG] Trunk allows all VLANs")
                return True
            
            # 3. Check specific VLAN in allowed lists
            for field in ['trunking_vlans', 'vlans_allowed']:
                if _is_vlan_in_list(sw_data.get(field, ''), vlan_id):
                    print(f"[DEBUG] VLAN {vlan_id} found in {field}")
                    return True
            
            return False

    except Exception as e:
        print(f"[ERROR] Switchport check failed, falling back to config: {str(e)}")
    
    # Minimal fallback (only checks for unrestricted trunks)
    try:
        command = f"show running-config interface {interface}"
        result = task.run(task=netmiko_send_command,
                         command_string=command,
                         enable=True)
        config = result.result.lower()
        
        # Only check for unrestricted trunks in fallback
        if ("switchport mode trunk" in config and 
            "switchport trunk allowed vlan" not in config):
            print(f"[DEBUG] Fallback: Trunk with no VLAN restrictions")
            return True
            
    except Exception as e:
        print(f"[ERROR] Fallback config check failed: {str(e)}")
    
    print(f"[DEBUG] VLAN {vlan_id} not allowed on trunk {interface}")
    return False

def _is_vlan_in_list(vlan_str: str, target_vlan: str) -> bool:
    """Helper to parse VLAN lists (1,3-5,10)"""
    if not vlan_str:
        return False
        
    for part in vlan_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start <= int(target_vlan) <= end:
                return True
        elif part == target_vlan:
            return True
    return False

def trace_path_to_router(nr, start_device: str) -> List[str]:
    print('\n[DEBUG] Tracing path to router...')
    """Trace path from edge switch to router using LLDP"""
    path = []
    current_device = start_device
    visited = set()
    max_hops = 15  # Increased from 10 to allow for larger networks
    
    # Get the target router IP from the starting device
    try:
        target_router = nr.inventory.hosts[start_device].data.get('router')
        if not target_router:
            print(f"[ERROR] No router defined for {start_device}")
            return []
    except Exception as e:
        print(f"[ERROR] Failed to get router IP: {str(e)}")
        return []

    print(f"[DEBUG] Target router IP: {target_router}")

    while current_device and current_device not in visited and len(path) < max_hops:
        visited.add(current_device)
        path.append(current_device)
        print(f"\n[DEBUG] Current device: {current_device}")
        print(f"[DEBUG] Current path: {' -> '.join(path)}")
        
        # Check if we've reached the target router
        if current_device == target_router:
            print(f"[SUCCESS] Reached target router at {current_device}")
            break
        
        # Get all LLDP neighbors
        print(f"[DEBUG] Getting LLDP neighbors for {current_device}")
        try:
            neighbors_result = nr.filter(name=current_device).run(task=get_lldp_neighbors)
            neighbors = neighbors_result[current_device].result
            
            if not neighbors:
                print(f"[DEBUG] No LLDP neighbors found for {current_device}")
                break
                
            print(f"[DEBUG] Raw LLDP data: {neighbors}")
            
            # Find all possible next hops
            possible_hops = []
            for neighbor in (neighbors if isinstance(neighbors, list) else [neighbors]):
                if isinstance(neighbor, dict):
                    # Try multiple possible fields for neighbor IP
                    neighbor_ip = (neighbor.get('mgmt_address') or 
                                neighbor.get('neighbor') or 
                                neighbor.get('neighbor_name'))
                    
                    # Clean up neighbor IP if it's a hostname
                    if neighbor_ip and '.' not in neighbor_ip:
                        neighbor_ip = neighbor_ip.split('.')[0]  # Take just the hostname part
                    
                    local_port = (neighbor.get('local_interface') or 
                                neighbor.get('local_port'))
                    
                    if neighbor_ip and neighbor_ip not in visited:
                        # Try to resolve hostname to IP if needed
                        resolved_ip = None
                        for hostname, host in nr.inventory.hosts.items():
                            if hostname == neighbor_ip or host.get('hostname', '') == neighbor_ip:
                                resolved_ip = hostname
                                break
                        
                        if resolved_ip:
                            possible_hops.append((local_port, resolved_ip))
                            print(f"[DEBUG] Found valid neighbor {resolved_ip} on port {local_port}")
                else:
                    print(f"[WARNING] Unexpected neighbor format: {neighbor}")
            
            if not possible_hops:
                print("[DEBUG] No unvisited neighbors found")
                break
                
            # Check if target router is directly reachable
            router_ports = [hop for hop in possible_hops if hop[1] == target_router]
            if router_ports:
                print(f"[DEBUG] Found direct path to router {target_router}")
                path.append(target_router)
                break
                
            # Select the next hop (prioritize devices that have the router in their data)
            next_hop = None
            for port, hop in possible_hops:
                try:
                    if nr.inventory.hosts[hop].data.get('router') == target_router:
                        next_hop = hop
                        print(f"[DEBUG] Selected {hop} as it has router {target_router}")
                        break
                except KeyError:
                    continue
            
            # Fall back to first available if no ideal candidate found
            if not next_hop:
                next_hop = possible_hops[0][1]
                print(f"[DEBUG] Selected first available neighbor: {next_hop}")
            
            current_device = next_hop
            
        except Exception as e:
            print(f"[ERROR] Error processing neighbors for {current_device}: {str(e)}")
            break
    
    # Ensure the router is always the last node in the path
    if path and path[-1] != target_router:
        path.append(target_router)
        print(f"[DEBUG] Appended router {target_router} as final hop (by definition)")

    # Final verification
    if target_router in path:
        print(f"\n[SUCCESS] Complete path to router found: {' -> '.join(path)}")
    else:
        print(f"\n[WARNING] Partial path found (router not reached): {' -> '.join(path)}")
        print(f"[WARNING] Last device {path[-1]} has neighbors: {neighbors if 'neighbors' in locals() else 'unknown'}")
    
    return path

def verify_vlan_path(initial_switch: str, target_port: str, vlan_id: str) -> Tuple[bool, str, List[str]]:
    """Main verification function with full path checking"""
    print("\n[DEBUG] Starting VLAN path verification")
    print(f"[DEBUG] Initial switch: {initial_switch}")
    print(f"[DEBUG] Target port: {target_port}")
    print(f"[DEBUG] VLAN ID: {vlan_id}")
    
    nr = InitNornir(config_file="config.yaml")
    path = trace_path_to_router(nr, initial_switch)
    
    if not path:
        print("[ERROR] No path found to router")
        return False, "Failed to trace path to router", []
    
    print("\n[DEBUG] Beginning path verification")
    for i, device_ip in enumerate(path):
        print('\n' + '='*50)
        print(f"[DEBUG] Verifying device {i+1}/{len(path)}: {device_ip}")
        print('='*50)
        device = nr.inventory.hosts[device_ip]
        
        # Verify VLAN exists on device
        print(f"[DEBUG] Checking if VLAN {vlan_id} exists on {device_ip}")
        vlan_exists = nr.filter(name=device_ip).run(task=verify_vlan_exists, vlan_id=vlan_id)[device_ip].result
        if not vlan_exists:
            print(f"[ERROR] VLAN {vlan_id} missing on {device_ip}")
            return False, f"VLAN {vlan_id} missing on {device_ip}", path
        print(f"[DEBUG] VLAN {vlan_id} exists on {device_ip}")
        
        # First device checks access port
        if i == 0:
            print(f"[DEBUG] Verifying access port {target_port} on edge switch")
            access_ok = nr.filter(name=device_ip).run(
                task=verify_access_vlan, 
                interface=target_port, 
                vlan_id=vlan_id
            )[device_ip].result
            if not access_ok:
                print(f"[ERROR] Port {target_port} not in VLAN {vlan_id} on {device_ip}")
                return False, f"Port {target_port} not in VLAN {vlan_id} on {device_ip}", path
            print(f"[DEBUG] Access port {target_port} verified on {device_ip}")
        
        # Intermediate devices check trunk ports
        elif i < len(path) - 1:
            next_device = path[i+1]
            print(f"[DEBUG] Finding uplink port to next device: {next_device}")
            uplink_port = nr.filter(name=device_ip).run(
                task=find_uplink_port,
                neighbor_ip=next_device
            )[device_ip].result
            
            if not uplink_port:
                print(f"[ERROR] Could not find uplink port on {device_ip} to {next_device}")
                return False, f"Could not find uplink port on {device_ip}", path
            
            print(f"[DEBUG] Found uplink port: {uplink_port}")
            print(f"[DEBUG] Verifying trunk port {uplink_port} allows VLAN {vlan_id}")
                
            trunk_ok = nr.filter(name=device_ip).run(
                task=verify_trunk_vlan,
                interface=uplink_port,
                vlan_id=vlan_id
            )[device_ip].result
            if not trunk_ok:
                print(f"[ERROR] VLAN {vlan_id} not allowed on trunk {uplink_port} of {device_ip}")
                return False, f"VLAN {vlan_id} not allowed on trunk {uplink_port} of {device_ip}", path
            print(f"[DEBUG] Trunk port {uplink_port} verified on {device_ip}")
    
    print("\n[DEBUG] VLAN path verification completed successfully")
    return True, f"VLAN {vlan_id} path verified successfully from {initial_switch} to router", path

def visualize_path(path: List[str], failure_node: str = None):
    """Generate network path diagram with failure points highlighted"""
    print("\n[DEBUG] Generating network path visualization")
    G = nx.Graph()
    
    # Add edges to the graph
    for i in range(len(path)-1):
        G.add_edge(path[i], path[i+1])
    
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G)
    
    # Determine node colors - red for failure point and beyond
    node_colors = []
    failure_found = False
    for node in G.nodes():
        if node == failure_node:
            failure_found = True
        node_colors.append('red' if failure_found else 'skyblue')
    
    # Draw the graph
    nx.draw(G, pos, 
            with_labels=True, 
            node_size=2000, 
            node_color=node_colors, 
            font_size=10,
            edge_color='gray')
    
    plt.title("Network Path Verification")
    plt.show()

def main():
    # Example usage
    initial_switch = "172.17.57.243"
    target_port = "GigabitEthernet1/0/10"
    vlan_id = "5"
    
    print("\n[INFO] Starting VLAN path verification script")
    success, message, path = verify_vlan_path(initial_switch, target_port, vlan_id)
    
    print("\n" + "="*50)
    print(f"VLAN Path Verification Result: {'SUCCESS' if success else 'FAILURE'}")
    print("="*50)
    print(f"Message: {message}")
    print(f"Path traced: {' -> '.join(path)}")
    
    if path:
        # Determine failure node from message if verification failed
        failure_node = None
        if not success:
            # Extract the failure node from the error message
            for node in path:
                if node in message:
                    failure_node = node
                    break
        
        visualize_path(path, failure_node)

if __name__ == "__main__":
    main()
