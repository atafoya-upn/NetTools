#!/usr/bin/python3

###############################################################################
#   ring_walk.py Ver 1.0                                                      #
#   Author: Adam Tafoya                                                       #
# Dependencies:                                                               # 
#   Python3.9 or higher                                                       #
#   Netmiko                                                                   #
# Script Description:                                                         #
#   This Python script will walk the ring when provided IP(s) for the core    #
#   router(s) and the name of the ring. If the ring aggregates on a single    #
#   hub, you will enter one ip at the first prompt and just press enter again #
#   at the second prompt. There will be a confirmation prompt if you don't    #
#   enter a second IP. If the ring aggregates to a dual hub, be sure to enter #
#   the second IP or the script will attempt to gather circuit IDs for all    #
#   services on the second agg router (shouldn't cause any issues, but may    #
#   lead to the script ending prematurely if there are a lot of services on   #
#   the agg router and it takes too long to pull the configs). After entering #
#   the IPs, you will be prompted to enter a ring ID. This must be in the     #
#   correct format. A function was created with some validation and error     #
#   handling that should allow you to keep trying if it is not in the correct #
#   format. The script connects to the first router ip that was entered and   #
#   looks for the ring ID in the interface descriptions to determine the      #
#   interfaces that the ring is configured on. If it is the first core router #
#   the script will set the next node to connect to as the neighbor on the    #
#   first ring port that it finds for that ring as long as that neighbor ID   #
#   is not an IP that was entered by the user as one of the core routers. If  #
#   it is, then it will grab the ip from the next ring port it found. It will #
#   continue to connect to the next router on the ring, making that           #
#   determination based on matches to the previous router it connected to. It #
#   stops when it finds the previous router on one ring port and the first    #
#   on the other ring port. The script gathers device hostnames, the loopback #
#   IPs (or router ID), the device model, IOS version, ROMMON version, ring   #
#   port interface IDs, P2P IPs on the ring ports, and neighbor IDs on the    #
#   ring ports. It also gathers CKIDs for all services on each device except  #
#   for the core/aggregate routers. Some information is output regularly to   #
#   so the user doesn't assume the script stopped running as it can take      #
#   up to 20 minutes or so for this script to complete on larger rings. Two   #
#   files will be created with all the collected data sorted. The script will #
#   not prompt you for a specific directory but you can change it by editing  #
#   the save_directory variable near the bottom of the main function. Devices #
#   will be listed in the order that they appear on the ring.                 #
#                                                                             #
# To do:                                                                      #
#   - I plan to add a function using pandas to create an excel file where all #
#     the data will be well sorted.                                           #
#   - Will add a function probably using VisioAutomation to create a diagram  #
#     of the ring but might script that out seperately to avoid the need for  #
#     Visio to be installed if a user doesn't have it or would prefer to map  #
#     out the network in a different program.                                 #
###############################################################################

import re
import sys
from getpass import getpass
from netmiko import SSHDetect, ConnLogOnly
from datetime import datetime
import logging
import ipaddress
from pathlib import Path
from importlib.util import find_spec
import json
import tkinter as tk
from tkinter import filedialog

if sys.version_info < (3, 9):
    sys.exit("This script requires Python 3.9 or higher!")


def get_dir_path():
    while True:
        try:
            # Create a root window (hidden)
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            
            # Open the file dialog
            file_directory = filedialog.askdirectory(
                parent=root,
                initialdir=str(Path.home()),
                title='Select a Directory'
                )

            # Destroy the root window to clean up
            root.destroy()

            if file_directory:
                print(type(file_directory))
                return file_directory
            else:
                print("No directory selected.")
                sys.exit()
        except Exception as e:
            print("An unexpected error occurred:", e)
            exit()


def get_core_router_ips():
    """
    Prompts the user to enter the IP address(es) for one or two aggregate routers.
    Returns:
        A tuple (router_core01, router_core02) where:
            - router_core01: (str) the first valid IP address.
            - router_core02: (str) the second valid IP address if provided; otherwise None.
    """
    # Prompt for the first IP address until a valid IP is entered.
    while True:
        r1 = input("Enter the IP address of the first core router for the ring: ").strip()
        if not r1:
            print("You must enter at least one IP address. Please try again.")
            continue
        try:
            ipaddress.ip_address(r1)
        except ValueError:
            print("Invalid IP address format. Please try again.")
            continue
        router_core01 = r1
        break

    # Prompt for the second IP address.
    # If the user does not enter anything, ask for confirmation.
    while True:
        r2 = input("Enter the IP address of the second core router. "
                   "If both sides of the ring aggregate on the same device, just press enter: ").strip()
        if not r2:
            confirm = input("You only entered one IP. "
                            "Type 'y' or 'yes' to confirm the ring aggregates to only one router. (y/n): ").strip().lower()
            if confirm.startswith("y"):
                router_core02 = None
                break
            else:
                # If the user does not confirm, loop back to ask for the second IP.
                continue
        try:
            ipaddress.ip_address(r2)
        except ValueError:
            print("Invalid IP address format. Please try again.")
            continue
        router_core02 = r2
        break

    return (router_core01, router_core02)


def get_ring_id():
    """
    Prompts the user to enter a ring ID with the required format:
      - 4 letters (A-Z),
      - a dash,
      - the literal "MOE",
      - a dash,
      - and 2 digits.
      
    If the user enters a ring ID that contains "COE" instead of "MOE",
    they are notified that this function is only for walking MOE rings
    and given the option to quit or try again.
    
    Returns:
        A valid ring ID string in the format AAAA-MOE-00.
    """
    # Define patterns:
    moe_pattern = re.compile(r'^(?P<prefix>[A-Z]{4})-MOE-(?P<suffix>\d{2}(-P)?)$')
    coe_pattern = re.compile(r'^(?P<prefix>[A-Z]{4})-COE-(?P<suffix>\d{2}(-P)?)$')
    
    while True:
        ring_id_input = input("Enter the ring ID (format: AAAA-MOE-00): ").strip().upper()
        
        # Check for valid MOE ring ID.
        if moe_pattern.fullmatch(ring_id_input):
            return ring_id_input
        
        # Check if the user entered a COE ring ID.
        if coe_pattern.fullmatch(ring_id_input):
            print("This function is only designed for walking MOE rings and will not work for a COE ring.")
            choice = input("Would you like to quit the program? (y/n): ").strip().lower()
            if choice.startswith("y"):
                sys.exit("Quitting the program.")
            else:
                # Allow the user to try entering a valid ring ID again.
                continue
        
        # If the format doesn't match either pattern.
        print("Invalid ring ID format. Please ensure it follows the format: AAAA-MOE-00 (e.g., TEMP-MOE-02).")


def guess_dev_type(ip):
    """
    Connects to a device using the provided IP address and device parameters.
    Automatically detects the device type based on the SSH connection.

    Parameters:
        ip (str): The IP address of the device.

    Returns:
        str: The best match device type based on the SSH connection.
    """

    device = {
        "device_type": "autodetect",
        "ip": ip,
        "username": username,
        "password": password,
    }

    guesser = SSHDetect(**device)
    best_match = guesser.autodetect()

    return best_match


def device_connect(ip, device_type):
    """
    Connects to a device using the provided IP address and device parameters.

    Args:
        ip (str): The IP address of the device.
        device_type (str): The type of the device.

    Returns:
        ConnLogOnly: A connection object to the device.

    This function creates a device dictionary with the provided IP address,
    device type, username, password, and various connection parameters. It
    then creates a connection object using the ConnLogOnly class, passing in
    the device dictionary and logging parameters. The connection object is
    then returned.
    """

    device = {
        "device_type": device_type,
        "ip": ip,
        "username": username,
        "password": password,
        "auto_connect": False,
        "fast_cli": False,
        "keepalive": 30,
        "session_timeout": 1800,
        "conn_timeout": 300,
        "banner_timeout": 180,
        "auth_timeout": 180,
        "blocking_timeout": 2400,
        "global_delay_factor": 2.0,
        "session_log_file_mode": "write",
    }

    connection = ConnLogOnly(
        log_file="ring_walk.log",
        log_level=logging.DEBUG,
        log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        **device,
    )

    return connection


def xe_device_info(connection, ring_id, template_dir, collect_CKIDs = True):

    # Set textfsm template files
    plat_diag_tmpl_file = Path("cisco_ios_show_platform_diag.textfsm")
    version_tmpl_file = Path("cisco_ios_show_version.textfsm")
    if_desc_tmpl_file = Path("cisco_ios_show_interfaces_description.textfsm")
    ip_if_brief_file = Path("cisco_ios_show_ip_interface_brief.textfsm")
    ip_ospf_ne_file = Path("cisco_ios_show_ip_ospf_neighbor.textfsm")
    # Set paths to textfsm templates
    plat_diag_tmpl_path = str(template_dir / plat_diag_tmpl_file)
    version_tmpl_path = str(template_dir / version_tmpl_file)
    if_desc_tmpl_path = str(template_dir / if_desc_tmpl_file)
    ip_if_brief_path = str(template_dir / ip_if_brief_file)
    ip_ospf_ne_path = str(template_dir / ip_ospf_ne_file)

    # Define and compile regex patterns
    ckid_pattern = re.compile(
        r"([A-Z]{6}\w{2}[-/][A-Z]{3}\w{3}[-/][A-Z]{6}\w{2})"
        )
    voice_pattern = re.compile(
        r"(?:description.*)(WL.?[0-9]{5})"
        )
    ip_regex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        )

    # Set variables for commands
    plat_cmd = "show platform diag"
    ver_cmd = "show version"
    if_des_cmd = "show interfaces description"
    ip_if_cmd = "show ip interface brief"
    ospf_ne_cmd = "show ip ospf neighbor"
    sh_run_cmd = "show run"
    voice_cmd = r"show ip route vrf VOICE | i directly connected"

    try:
        # Establish connection
        connection.establish_connection()

        # Send commands
        h_name = connection.find_prompt()[:-1]
        plat_out = connection.send_command(
            plat_cmd,
            use_textfsm=True,
            textfsm_template=plat_diag_tmpl_path
            )
        ver_out = connection.send_command(
            ver_cmd,
            use_textfsm=True,
            textfsm_template=version_tmpl_path
            )
        if_des_out = connection.send_command(
            if_des_cmd,
            use_textfsm=True,
            textfsm_template=if_desc_tmpl_path
            )
        ring_ports = []
        # Consider grabbing service interface IDs here for collecting service configs
        for if_line in if_des_out:
            if ring_id in if_line["description"]:
                ring_ports.append(if_line["port"])
            else:
                continue
        if len(ring_ports) != 2:
            print("Error: Device is either not on a ring or interface " \
                  "descriptions don't match the provided input.")
            sys.exit("Quitting the program.")
        else:
            ring_if1 = ring_ports[0]
            ring_if2 = ring_ports[1]
            if_ip_out1 = connection.send_command(
                f"{ip_if_cmd} {ring_if1}"
            )
            ospf_ne_out1 = connection.send_command(
                f"{ospf_ne_cmd} {ring_if1}"
            )
            if_ip_out2 = connection.send_command(
                f"{ip_if_cmd} {ring_if2}"
            )
            ospf_ne_out2 = connection.send_command(
                f"{ospf_ne_cmd} {ring_if2}"
            )
            dev_id_out = connection.send_command(
                f"{ip_if_cmd} Lo0"
            )
            
        # Gather CKIDs if not on core router
        if collect_CKIDs:
            connection.send_command("terminal length 0")
            running_cfg = connection.send_command(sh_run_cmd, read_timeout=90)
            voice_check = connection.send_command(voice_cmd)
        
        # Disconnect
        connection.disconnect()
        
    except Exception as e:
        print(e)

    try:
        # Run additional parsing and finish putting data together
        # Get Router ID
        dev_id_match = ip_regex.findall(dev_id_out)
        if len(dev_id_match) != 1:
            print(dev_id_match)
        # Get interface details
        if1_ip = ip_regex.findall(if_ip_out1)
        if len(if1_ip) != 1:
            print(if1_ip)
        if1_neighbor = ip_regex.findall(ospf_ne_out1)
        if len(if1_neighbor) !=2:
            print(if1_neighbor)
        if2_ip = ip_regex.findall(if_ip_out2)
        if len(if2_ip) != 1:
            print(if2_ip)
        if2_neighbor = ip_regex.findall(ospf_ne_out2)
        if len(if2_neighbor) !=2:
            print(if2_neighbor)
        # Parse data for CKIDs if collected, otherwise return empty list
        if collect_CKIDs:
            # Extract circuit IDs from running configuration
            ckids = ckid_pattern.findall(running_cfg)
            # Remove dashes from circuit IDs
            updated_list = [s.replace("-", "/") for s in ckids]
            # Remove duplicates
            circuit_ids = list(set(updated_list))
            # Check if voice circuit is present
            if 'directly connected' in voice_check:
                circuit_ids.extend(voice_pattern.findall(running_cfg))
        else:
            circuit_ids = []
        
        # Dictionary for returning ordered data
        device_info = {
            "hostname": h_name,
            "router_id": dev_id_match[0],
            "chassis": plat_out[0]["chassis_type"],
            "ios_ver": ver_out[0]["version"],
            "rom_version": plat_out[0]["firmware_version"],
            "ring_if1": {
                "if_id": ring_if1,
                "if_ip": if1_ip[0],
                "neighbor": if1_neighbor[0]
                },
            "ring_if2": {
                "if_id": ring_if2,
                "if_ip": if2_ip[0],
                "neighbor": if2_neighbor[0]
                },
            "ckid_list": circuit_ids
            }
        
        return device_info
    
    except Exception as e:
        print(e)


def xr_device_info(connection, ring_id, template_dir, collect_CKIDs = True):

    # Set textfsm template paths
    if_desc_tmpl_file = Path("cisco_xr_show_interfaces_description.textfsm")
    if_desc_tmpl_path = str(template_dir / if_desc_tmpl_file)

    # Define and compile regex patterns
    chassis_pattern = re.compile(
        r"(N540X?-[A26][C8Z][CZ1][48]?[CG]?-SYS-?[AD]?)"
        )
    version_pattern = re.compile(
        r"(?:\s+Version\s+\:\s)(\d\.\d\.\d)"
        )
    ckid_pattern = re.compile(
        r"([A-Z]{6}\w{2}[-/][A-Z]{3}\w{3}[-/][A-Z]{6}\w{2})"
        )
    voice_pattern = re.compile(
        r"(?:description.*)(WL.?[0-9]{5})"
        )
    ip_regex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        )
    
    # Set variables for commands
    dev_id_cmd = "show router-id"
    plat_cmd = "admin show platform"
    ver_cmd = "show version"
    if_des_cmd = "show interfaces description"
    ip_if_cmd = "show ip interface"
    ospf_ne_cmd = "show ip ospf neighbor"
    sh_run_cmd = "show run"
    voice_cmd = r"show ip route vrf VOICE | i directly connected"

    try:
        # Establish connection
        connection.establish_connection()
        # Send commands
        h_name = connection.find_prompt()[:-1].split(":")[1]
        dev_id_out = connection.send_command(dev_id_cmd)
        platform = connection.send_command(plat_cmd)
        version = connection.send_command(ver_cmd)
        if_desc_output = connection.send_command(
            if_des_cmd,
            use_textfsm=True,
            textfsm_template=if_desc_tmpl_path
            )
        ring_ports = []
        # Consider grabbing service interface IDs here for collecting service configs
        for if_line in if_desc_output:
            if ring_id in if_line["description"]:
                ring_ports.append(if_line["interface"])
            else:
                continue
        if len(ring_ports) != 2:
            print("Error: Device is either not on a ring or interface " \
                  "descriptions don't match the provided input.")
            sys.exit("Quitting the program.")
        else:
            ring_if1 = ring_ports[0]
            ring_if2 = ring_ports[1]
            if_ip_out1 = connection.send_command(
                f"{ip_if_cmd} {ring_if1} brief"
            )
            ospf_ne_out1 = connection.send_command(
                f"{ospf_ne_cmd} {ring_if1}"
            )
            if_ip_out2 = connection.send_command(
                f"{ip_if_cmd} {ring_if2} brief"
            )
            ospf_ne_out2 = connection.send_command(
                f"{ospf_ne_cmd} {ring_if2}"
            )
            
        # Gather CKIDs if not on core router
        if collect_CKIDs:
            connection.send_command("terminal length 0")
            running_cfg = connection.send_command(sh_run_cmd, read_timeout=60)
            voice_check = connection.send_command(voice_cmd)
        
        # Disconnect
        connection.disconnect()

    except Exception as e:
        print(e)

    try:
        # Run additional parsing and finish putting data together
        # Get Router ID
        dev_id_match = ip_regex.findall(dev_id_out)
        if len(dev_id_match) != 1:
            print(dev_id_match)
        # Get interface details
        if1_ip = ip_regex.findall(if_ip_out1)
        if len(if1_ip) != 1:
            print(if1_ip)
        if1_neighbor = ip_regex.findall(ospf_ne_out1)
        if len(if1_neighbor) !=2:
            print(if1_neighbor)
        if2_ip = ip_regex.findall(if_ip_out2)
        if len(if2_ip) != 1:
            print(if2_ip)
        if2_neighbor = ip_regex.findall(ospf_ne_out2)
        if len(if2_neighbor) !=2:
            print(if2_neighbor)
        # Parse data for CKIDs if collected, otherwise return empty list
        if collect_CKIDs:
            # Extract circuit IDs from running configuration
            ckids = ckid_pattern.findall(running_cfg)
            # Remove dashes from circuit IDs
            updated_list = [s.replace("-", "/") for s in ckids]
            # Remove duplicates
            circuit_ids = list(set(updated_list))
            # Check if voice circuit is present
            if 'directly connected' in voice_check:
                circuit_ids.extend(voice_pattern.findall(running_cfg))
        else:
            circuit_ids = []
        
        # Dictionary for returning ordered data
        device_info = {
            "hostname": h_name,
            "router_id": dev_id_match[0],
            "chassis": chassis_pattern.search(platform).group(1),
            "ios_ver": version_pattern.search(version).group(1),
            "rom_version": "",
            "ring_if1": {
                "if_id": ring_if1,
                "if_ip": if1_ip[0],
                "neighbor": if1_neighbor[0]
                },
            "ring_if2": {
                "if_id": ring_if2,
                "if_ip": if2_ip[0],
                "neighbor": if2_neighbor[0]
                },
            "ckid_list": circuit_ids
            }
        
        return device_info
    
    except Exception as e:
        print(e)


def main():

    # Get the username and password from the user
    global username
    global password
    print("Enter your username:")
    username = input("Username: ")
    print("Enter your password:")
    password = getpass()
    # Get the IP(s) of the hubs from the user
    core_ips = get_core_router_ips()
    # Get ring id. Must be in the form AAAA-MOE-##. Does not work on COE rings.
    ring_id = get_ring_id()
    # Track time until completion
    start_time = datetime.now()
    # Find ntc_templates directory for use in parsing with textfsm
    spec = find_spec("ntc_templates")
    templates_dir = Path(spec.submodule_search_locations[0]) / Path("templates")
    all_dev_info = []
    ckid_full_list = []
    agg_router01 = core_ips[0]
    if core_ips[1]:
        agg_router02 = core_ips[1]
        print("Dual Hub Ring")
        print(f"Agg 1: {agg_router01}")
        print(f"Agg 2: {agg_router02}")
    else:
        agg_router02 = core_ips[0]
        print("Single Hub Ring")
        print(f"Agg: {agg_router01}")
    # Pause before opening file dialog to choose a save folder
    input("Press enter to open a dialog box and choose a folder for saving" \
          "device and circuit ID files...")
    # Define target directory to save files
    save_directory = Path(get_dir_path())
    print(f"Attempting to walk {ring_id} starting at {agg_router01}...")
    router = None
    previous_router = None
    last_router = False
    dev_count = 0
    while last_router != True:
        try:
            if not router:
                router = agg_router01
            if router in core_ips:
                collect_CKIDs = False
            else:
                collect_CKIDs = True
                dev_count += 1
            print("Figuring out device type...")
            # Get the best match device type based on the SSH connection
            ios_type = guess_dev_type(router)
            print("Setting up connection...")
            connection = device_connect(router, ios_type)
            print(f"Gathering device information ({router})...")
            # Gather device info based on ios_type
            # Gather info from XE device
            if ios_type == "cisco_xe":
                device_info = xe_device_info(connection, ring_id, templates_dir, collect_CKIDs)
                # If CKIDs were collected, add to full ckid list
                if device_info['ckid_list']:
                    temp_list = device_info.pop('ckid_list')
                    ckid_full_list.extend(temp_list)
                all_dev_info.append(device_info)
                formatted_info = f"Device Information:\n" \
                    f"Hostname: {device_info['hostname']}\n" \
                    f"Router ID: {device_info['router_id']}\n" \
                    f"Chassis: {device_info['chassis']}\n" \
                    f"IOS: {device_info['ios_ver']}\n" \
                    f"ROMMON: {device_info['rom_version']}\n" \
                    f"Interface {device_info['ring_if1']['if_id']}:\n" \
                    f"    IP: {device_info['ring_if1']['if_ip']}\n" \
                    f"    Neighbor: {device_info['ring_if1']['neighbor']}\n" \
                    f"Interface {device_info['ring_if2']['if_id']}:\n" \
                    f"    IP: {device_info['ring_if2']['if_ip']}\n" \
                    f"    Neighbor: {device_info['ring_if2']['neighbor']}"
            # Gather info from XR device    
            elif ios_type == "cisco_xr":
                device_info = xr_device_info(connection, ring_id, templates_dir, collect_CKIDs)
                # If CKIDs were collected, format list to display one CKID per line
                if device_info['ckid_list']:
                    temp_list = device_info.pop('ckid_list')
                    ckid_full_list.extend(temp_list)
                all_dev_info.append(device_info)
                formatted_info = f"Device Information:\n" \
                    f"Hostname: {device_info['hostname']}\n" \
                    f"Router ID: {device_info['router_id']}\n" \
                    f"Chassis: {device_info['chassis']}\n" \
                    f"IOS: {device_info['ios_ver']}\n" \
                    f"Interface {device_info['ring_if1']['if_id']}:\n" \
                    f"    IP: {device_info['ring_if1']['if_ip']}\n" \
                    f"    Neighbor: {device_info['ring_if1']['neighbor']}\n" \
                    f"Interface {device_info['ring_if2']['if_id']}:\n" \
                    f"    IP: {device_info['ring_if2']['if_ip']}\n" \
                    f"    Neighbor: {device_info['ring_if2']['neighbor']}"
            # If not running Cisco XE or Cisco XR, print ios_type and move to next router in the list    
            else:
                print(
                    "Device is not a supported model\n" \
                    f"Device type: {ios_type}"
                    )
                print("Cannot continue to walk the ring. Check for any issues and try again.")
                break
            
            # Check if current router is the starting router
            if not previous_router:
                previous_router = router
                # If first neighbor ID is the second agg router,
                # set next router IP to the second neighbor.
                # Otherwise, set next router IP to first neighbor.
                if device_info['ring_if1']['neighbor'] == agg_router02:
                    router = device_info['ring_if2']['neighbor']
                else:
                    router = device_info['ring_if1']['neighbor']
            # If the first neighbor IP is the same as the previous router
            # but the current router is one of the core routers, it will be
            # the last router on the ring
            elif device_info['ring_if1']['neighbor'] == previous_router:
                if router in core_ips:
                    last_router = True
                # If the current router is not a core router, but the next
                # router is the first core router, this is a single hub ring
                # and this is the last router on the ring. Otherwise, set
                # the next router to the second neighbor.
                else:
                    if device_info['ring_if2']['neighbor'] == agg_router01:
                        last_router = True
                    else:
                        previous_router = router
                        router = device_info['ring_if2']['neighbor']
            # The first neighbor should be the next router on the ring. However,
            # if the current router is a core router, it is the second core router
            # and it will be the last one checked.
            else:
                if router in core_ips:
                    last_router = True
                # If the current router is not agg_router02, but the next neighbor
                # is agg_router01, this is a single hub ring and this is the last
                # router. Otherwise, set the next router to the first neighbor.
                else:
                    if device_info['ring_if1']['neighbor'] == agg_router01:
                        last_router = True
                    else:
                        previous_router = router
                        router = device_info['ring_if1']['neighbor']

            # Output to ensure script is running the ring correctly
            print(f"\n{formatted_info}\n\n")

            
        except Exception as e:
            print(e)
    
    # Additional code for creating a file to store all_dev_info in a structured
    # format. Finally, print the time taken to finish.
    print(f"Creating saving files to: {save_directory}")
    # Define file names and add to save path
    dev_filename = Path(f"Dev_Info_{ring_id}.json")
    dev_file_path = save_directory / dev_filename
    ckid_filename = Path(f"CKIDs_{ring_id}.txt")
    ckid_file_path = save_directory / ckid_filename
    # Write device info to json
    with dev_file_path.open('w') as f:
        json.dump(all_dev_info, f, indent=4)
    # Write ckid list to txt
    with open(ckid_file_path, 'w') as f:
        for item in ckid_full_list:
            f.write(item + "\n")
    # Print basic dev info and CKIDs for copying to MR
    print("Devices:")
    for each_dev in all_dev_info:
        print(f"{each_dev['hostname']} - {each_dev['router_id']}")
    print("Circuit IDs:")
    for each_id in ckid_full_list:
        print(each_id)
    print(f"Number of devices on ring: {dev_count}")
    print("\n\nTime taken: ", datetime.now() - start_time)

if __name__ == "__main__":
    main()
