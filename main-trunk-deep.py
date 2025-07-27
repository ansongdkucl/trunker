from nornir import InitNornir
from nornir_netmiko import netmiko_send_command
from nornir.core.task import Task, Result
from typing import Dict, List, Tuple, Optional
import networkx as nx
import matplotlib.pyplot as plt
import re
import textwrap


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
    """
    Check if VLAN exists in database (vendor-neutral) with robust
    error checking.
    """
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
        
        result_data = result.result
        print(f"[DEBUG] VLAN check result on {task.host}: {result_data}")
        
        # FIX: Check the type and content of the result
        
        # Case 1: TextFSM parsed successfully, returning a list.
        # An empty list means the VLAN was not found.
        if isinstance(result_data, list):
            return bool(result_data) # bool([]) is False, which is correct.

        # Case 2: TextFSM failed, returning a string.
        # We must check the string for failure messages.
        if isinstance(result_data, str):
            if "not found" in result_data.lower() or "unrecognized" in result_data.lower():
                return False # Explicitly return False if an error message is found.
        
        # Case 3: Any other result (None, empty string, etc.) is a failure.
        return False
    
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
    """Verify trunk allows the VLAN with robust error handling"""
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
        
        # Handle TextFSM parse failure (raw string output)
        if isinstance(result.result, str):
            print("[DEBUG] TextFSM parsing failed, using raw output")
            if "trunking" in result.result.lower() and "vlans allowed: all" in result.result.lower():
                return True
            return str(vlan_id) in result.result
        
        # Handle successful TextFSM parsing
        if result.result and isinstance(result.result, list):
            sw_data = result.result[0]
            
            # Verify trunk mode
            if sw_data.get('mode', '').lower() != 'trunk':
                return False
            
            # Check for ALL VLANs allowed
            if any(field == 'ALL' 
                  for field in [sw_data.get('trunking_vlans', ''), 
                               sw_data.get('vlans_allowed', '')]):
                return True
            
            # Check specific VLAN in allowed lists
            for field in ['trunking_vlans', 'vlans_allowed']:
                vlans = sw_data.get(field, '')
                if vlans and _is_vlan_in_list(vlans, vlan_id):
                    return True
            
            return False

    except Exception as e:
        print(f"[ERROR] Switchport check failed: {str(e)}")
    
    # Minimal fallback (only checks for unrestricted trunks)
    try:
        command = f"show running-config interface {interface}"
        result = task.run(
            task=netmiko_send_command,
            command_string=command,
            enable=True
        )
        config = result.result.lower()
        
        if ("switchport mode trunk" in config and 
            "switchport trunk allowed vlan" not in config):
            return True
            
    except Exception as e:
        print(f"[ERROR] Fallback config check failed: {str(e)}")
    
    return False

def _is_vlan_in_list(vlan_str: str, target_vlan: str) -> bool:
    """Helper to safely parse VLAN lists"""
    try:
        if not vlan_str:
            return False
            
        for part in str(vlan_str).split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start <= int(target_vlan) <= end:
                    return True
            elif part == str(target_vlan):
                return True
        return False
    except Exception as e:
        print(f"[ERROR] VLAN list parsing failed: {str(e)}")
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

def verify_vlan_path(initial_switch: str, target_port: str, vlan_id: str) -> Tuple[bool, str, List[str], Dict[str, str]]:
    """Modified to check all nodes regardless of failures"""
    print("\n[INFO] Starting comprehensive VLAN path verification")
    nr = InitNornir(config_file="config.yaml")
    verification_results = {}
    overall_success = True
    failure_reason = ""
    
    path = trace_path_to_router(nr, initial_switch)
    
    if not path:
        return False, "No path found to router", [], {}

    print("\n[INFO] Beginning comprehensive verification")
    for i, device_ip in enumerate(path):
        print('\n' + '='*50)
        print(f"[DEVICE] Verifying device {i+1}/{len(path)}: {device_ip}")
        print('='*50)
        
        device_result = {}
        
        # Verify VLAN exists (all devices)
        vlan_exists = nr.filter(name=device_ip).run(
            task=verify_vlan_exists,
            vlan_id=vlan_id
        )[device_ip].result
        
        if not vlan_exists:
            msg = f"VLAN {vlan_id} missing"
            device_result['vlan_status'] = msg
            overall_success = False
            if not failure_reason:
                failure_reason = msg
            print(f"[FAIL] {msg}")
        else:
            device_result['vlan_status'] = "VLAN exists"
            print(f"[PASS] VLAN {vlan_id} present")

        # First device checks access port
        if i == 0:
            access_ok = nr.filter(name=device_ip).run(
                task=verify_access_vlan,
                interface=target_port,
                vlan_id=vlan_id
            )[device_ip].result
            
            if not access_ok:
                msg = f"Port {target_port} not in VLAN"
                device_result['port_status'] = msg
                overall_success = False
                if not failure_reason:
                    failure_reason = msg
                print(f"[FAIL] {msg}")
            else:
                device_result['port_status'] = "Port configured"
                print(f"[PASS] Access port correct")

        # Intermediate devices check trunk ports
                # All devices except the first (access port check) should check trunk
        if i > 0:
            if i < len(path):
                next_device = path[i] if i == len(path) - 1 else path[i+1]
                uplink_port = nr.filter(name=device_ip).run(
                    task=find_uplink_port,
                    neighbor_ip=next_device
                )[device_ip].result

                if uplink_port:
                    trunk_ok = nr.filter(name=device_ip).run(
                        task=verify_trunk_vlan,
                        interface=uplink_port,
                        vlan_id=vlan_id
                    )[device_ip].result

                    if not trunk_ok:
                        msg = f"VLAN blocked on {uplink_port}"
                        device_result['trunk_status'] = msg
                        overall_success = False
                        if not failure_reason:
                            failure_reason = msg
                        print(f"[FAIL] {msg}")
                    else:
                        device_result['trunk_status'] = f"Trunk {uplink_port} OK"
                        print(f"[PASS] Trunk verified")
                else:
                    msg = f"No uplink to {next_device}"
                    device_result['trunk_status'] = msg
                    overall_success = False
                    if not failure_reason:
                        failure_reason = msg
                    print(f"[FAIL] {msg}")


        # Router gets special status
        if device_ip == path[-1]:
            device_result['role'] = "Router endpoint"
            
        # Combine all status messages
        verification_results[device_ip] = "\n".join(
            f"{k}: {v}" for k,v in device_result.items()
        )

    # Final message
    if overall_success:
        final_msg = f"VLAN {vlan_id} path fully verified"
    else:
        final_msg = f"VLAN path issues detected: {failure_reason}"

    print("\n[SUMMARY] Verification complete")
    for device, status in verification_results.items():
        print("{}: {}".format(device, status.replace('\n', ' | ')))
    
    return overall_success, final_msg, path, verification_results

def visualize_path(path: List[str], verification_results: Dict[str, str]):
    """
    Visualize VLAN path with guaranteed label visibility by taking manual
    control of the plot's layout and padding.
    """
    if not path:
        print("[WARNING] Cannot visualize an empty path.")
        return

    plt.ioff()
    fig, ax = plt.subplots(figsize=(18, 12)) # Use subplots for better axis control

    # Create graph
    G = nx.path_graph(path)
    
    # --- 1. Node Styling and Label Preparation ---
    node_colors = []
    device_labels = {}
    status_labels = {}
    
    for node in G.nodes():
        raw_result = verification_results.get(node, "Status: Unknown")
        
        # Determine node color based on verification result
        if "VLAN exists" in raw_result and ("Port configured" in raw_result or ("Trunk" in raw_result and "blocked" not in raw_result.lower())):
            color = "lightgreen"
        elif "missing" in raw_result.lower() or "blocked" in raw_result.lower() or "not in vlan" in raw_result.lower():
            color = "red"
        else:
            color = "khaki" # Use khaki for unknown/partial status
        
        node_colors.append(color)
        device_labels[node] = node
        
        # Format the status label for clarity
        status_text = raw_result.replace('\n', ' | ')
        status_labels[node] = '\n'.join(textwrap.wrap(status_text, width=25)) # Wrap long text

    # --- 2. Drawing Elements ---
    pos = {node: (i, 0) for i, node in enumerate(path)}

    nx.draw_networkx_nodes(
        G, pos, ax=ax,
        node_color=node_colors,
        node_size=6000,
        edgecolors='black',
        linewidths=1.5
    )
    
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        width=3,
        edge_color='steelblue',
        arrows=True,
        arrowstyle='-|>',
        arrowsize=25
    )
    
    # Draw device names (inside the node)
    nx.draw_networkx_labels(
        G, pos, ax=ax,
        labels=device_labels,
        font_size=12,
        font_weight='bold',
        font_color='black'
    )
    
    # Draw status info (below the node)
    status_pos = {k: (v[0], v[1] - 0.15) for k, v in pos.items()}
    nx.draw_networkx_labels(
        G, status_pos, ax=ax,
        labels=status_labels,
        font_size=10,
        font_color='black',
        verticalalignment='top',
        bbox={'boxstyle': 'round,pad=0.5', 'facecolor': 'white', 'edgecolor': 'gray', 'alpha': 0.9}
    )

    # --- 3. Layout, Padding, and Finalization (KEY FIXES) ---
    
    # Add a title and legend
    ax.set_title("VLAN Path Verification", fontsize=20, pad=20)
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', label='Pass', markerfacecolor='lightgreen', markersize=15),
        plt.Line2D([0], [0], marker='o', color='w', label='Fail', markerfacecolor='red', markersize=15),
        plt.Line2D([0], [0], marker='o', color='w', label='Unknown/Partial', markerfacecolor='khaki', markersize=15)
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=12)

    # Manually expand the plot limits to create padding for labels
    # This is the most critical fix to prevent clipping.
    x_coords = [p[0] for p in pos.values()]
    y_coords = [p[1] for p in pos.values()]
    ax.set_xlim(min(x_coords) - 1, max(x_coords) + 1)
    ax.set_ylim(min(y_coords) - 1, max(y_coords) + 1)
    
    # Hide the axis borders
    plt.axis('off')
    
    # Adjust layout to prevent title/legend overlap
    plt.tight_layout()

    # --- 4. Save and Display ---
    output_file = "vlan_path_visualization.png"
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n[INFO] Visualization saved to {output_file}")
    
    plt.show(block=True)
    plt.ion()

def main():
    initial_switch = "172.17.57.243"  # Example starting switch IP
    target_port = "GigabitEthernet1/0/10"
    vlan_id = "909"
    
    # Correct unpacking of all 4 return values
    success, message, path, results = verify_vlan_path(
        initial_switch,
        target_port,
        vlan_id
    )
    
    print("\n" + "="*50)
    print(f"Verification {'SUCCEEDED' if success else 'FAILED'}")
    print("="*50)
    print(f"Path: {' → '.join(path)}")
    print(f"Status: {message}")
    
    if path:
        visualize_path(path, results)

if __name__ == "__main__":
    main()
