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


def print_red(message: str) -> None:
    """Prints the given message in red."""
    RED = "\033[31m"    # ANSI escape code for red
    RESET = "\033[0m"   # Reset to default color
    print(f"{RED}{message}{RESET}")


def print_yellow(message: str) -> None:
    """Prints the given message in yellow."""
    YELLOW = "\033[33m"  # ANSI escape code for yellow
    RESET = "\033[0m"    # Reset to default color
    print(f"{YELLOW}{message}{RESET}")


def get_dir_path():
    """Prompts the user to select a directory using a file dialog.

    Returns:
        str: The path of the selected directory.
            If no directory is selected, prints an error message and exits.
    """
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
                return file_directory
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
    moe_pattern = re.compile(r"^(?P<prefix>[A-Z]{4})-MOE-(?P<suffix>\d{2}(-P)?)$")
    coe_pattern = re.compile(r"^(?P<prefix>[A-Z]{4})-COE-(?P<suffix>\d{2}(-P)?)$")
    
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
    return guesser.autodetect()


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

    return ConnLogOnly(
        log_file="ring_walk.log",
        log_level=logging.DEBUG,
        log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        **device,
    )


def _get_ckids(connection):
    """Gets CKIDs from the device."""

    sh_run_cmd = "show run"
    voice_cmd = r"show ip route vrf VOICE | i directly connected"

    connection.send_command("terminal length 0")
    running_cfg = connection.send_command(sh_run_cmd, read_timeout=60)
    voice_check = connection.send_command(voice_cmd)

    ckid_pattern = re.compile(r"([A-Z]{6}\w{2}[-/][A-Z]{3}\w{3}[-/][A-Z]{6}\w{2})")
    voice_pattern = re.compile(r"(?:description.*)(WL.?[0-9]{5})")

    ckids = ckid_pattern.findall(running_cfg)
    updated_list = [s.replace("-", "/") for s in ckids]
    circuit_ids = list(set(updated_list))
    if 'directly connected' in voice_check:
        circuit_ids.extend(voice_pattern.findall(running_cfg))

    return circuit_ids


def _xe_get_device_info(connection, ring_id, template_dir):
    """Gets device information for Cisco XE devices."""

    # Set textfsm template files and paths
    tmpl_files = {
        "platform": ("cisco_ios_show_platform_diag.textfsm", "plat_diag_tmpl_path"),
        "version": ("cisco_ios_show_version.textfsm", "version_tmpl_path"),
        "interfaces": ("cisco_ios_show_interfaces_description.textfsm", "if_desc_tmpl_path"),
    }
    tmpl_paths = {
        name: str(template_dir / Path(file))
        for name, (file, _) in tmpl_files.items()
    }

    # Send commands and parse output
    h_name = connection.find_prompt()[:-1]
    outputs = {
        name: connection.send_command(
            f"show {name} {'diag' if name == 'platform' else 'description' if name == 'interfaces' else ''}",
            use_textfsm=True,
            textfsm_template=tmpl_paths[name],
        )
        for name, (file, path_var) in tmpl_files.items()
    }
    return (h_name, outputs)


def _xe_parse_device_info(outputs, ring_id, collect_CKIDs=True):
    """Parses device information for Cisco XE devices.

    If collect_CKIDs is False, no service interface processing is done and the
    returned service_ports list is empty, with all circuit flags set to False.
    """
    # Compile the regex for service descriptions
    serv_des_re = re.compile(
        r"(?P<aloc>[A-Z]{6}\w{2})/"
        r"(?P<circuitid>[A-Z]{3}\w{3})/"
        r"(?P<zloc>[A-Z]{6}\w{2})[-_]"
        r"(?P<bandwidth>\d{1,5}M)[-_]"
        r"(?P<actname>\S+)"
    )

    # Initialize lists and flags
    ring_ports = []
    service_ports = []  # Will remain empty if collect_CKIDs is False
    dia_circuit = False
    epl_circuit = False
    ela_circuit = False
    voice_circuit = False

    # Process each interface entry if it has a non-empty description.
    for if_line in outputs["interfaces"]:
        description = if_line.get("description", "")
        if not description:
            continue

        # Skip management interfaces
        if description == "MGT_UPS":
            continue

        # Check if the interface belongs to the ring
        if ring_id in description:
            ring_ports.append(if_line["port"])
        else:
            # If we're collecting CKIDs, process the service interface data.
            if collect_CKIDs:
                service_ports.append(if_line["port"])
                match = serv_des_re.search(description)
                if match:
                    circuitid = match.group("circuitid")
                    if circuitid.startswith("EIA") or circuitid.startswith("DIA"):
                        dia_circuit = True
                    elif any(circuitid.startswith(x) for x in ["EPL", "EPH", "UNP", "EVC"]):
                        epl_circuit = True
                    elif circuitid.startswith("ELA"):
                        ela_circuit = True
                else:
                    # If the regex doesn't match, assume this is a voice service.
                    voice_circuit = True

    # Validate that exactly two ring ports were found.
    if len(ring_ports) != 2:
        raise ValueError("Device is either not on a ring or interface descriptions don't match.")

    # Retrieve additional device information.
    plat_out = outputs["platform"]
    chassis = plat_out[0]["chassis_type"]
    firmware_version = plat_out[0]["firmware_version"]
    ver_out = outputs["version"]
    ios_ver = ver_out[0]["version"]

    # Return all collected values.
    return (
        chassis,
        ios_ver,
        firmware_version,
        ring_ports,
        service_ports,
        dia_circuit,
        epl_circuit,
        ela_circuit,
        voice_circuit,
    )


def _xe_get_interface_info(connection, ring_ports):
    """Gets interface information for Cisco XE devices."""

    ring_if1 = ring_ports[0]
    ring_if2 = ring_ports[1]

    ip_if_cmd = "show ip interface brief"
    ospf_ne_cmd = "show ip ospf neighbor"

    if_ip_out1 = connection.send_command(f"{ip_if_cmd} {ring_if1}")
    ospf_ne_out1 = connection.send_command(f"{ospf_ne_cmd} {ring_if1}")
    if_ip_out2 = connection.send_command(f"{ip_if_cmd} {ring_if2}")
    ospf_ne_out2 = connection.send_command(f"{ospf_ne_cmd} {ring_if2}")
    dev_id_out = connection.send_command(f"{ip_if_cmd} Lo0")

    return (dev_id_out, if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2)


def _xe_parse_interface_info(dev_id_out, if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2):
    """Parses interface information for Cisco XE devices."""

    ip_regex = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

    dev_id_match = ip_regex.findall(dev_id_out)
    if len(dev_id_match) != 1:
        raise ValueError("Invalid router ID output.")

    if1_ip = ip_regex.findall(if_ip_out1)
    if len(if1_ip) != 1:
        raise ValueError("Invalid interface 1 IP output.")
    if1_neighbor = ip_regex.findall(ospf_ne_out1)
    if len(if1_neighbor) != 2:
        raise ValueError("Invalid interface 1 neighbor output.")

    if2_ip = ip_regex.findall(if_ip_out2)
    if len(if2_ip) != 1:
        raise ValueError("Invalid interface 2 IP output.")
    if2_neighbor = ip_regex.findall(ospf_ne_out2)
    if len(if2_neighbor) != 2:
        raise ValueError("Invalid interface 2 neighbor output.")

    return (dev_id_match[0], if1_ip[0], if1_neighbor[0], if2_ip[0], if2_neighbor[0])


def xe_device_info(connection, ring_id, template_dir, collect_CKIDs=True):
    """Gets device information for Cisco XE devices."""

    try:
        connection.establish_connection()

        h_name, outputs = _xe_get_device_info(connection, ring_id, template_dir)
        chassis, ios_ver, rom_version, ring_ports, service_ports, \
            dia_circuit, epl_circuit, ela_circuit, voice_circuit = \
                _xe_parse_device_info(outputs, ring_id, collect_CKIDs)
        print(f"Service Ports: {service_ports}")
        print(f"DIA: {dia_circuit}")
        print(f"EPL: {epl_circuit}")
        print(f"ELA: {ela_circuit}")
        print(f"Voice: {voice_circuit}")
        router_id, if1_ip, if1_neighbor, if2_ip, if2_neighbor = \
            _xe_parse_interface_info(*_xe_get_interface_info(connection, ring_ports))
        circuit_ids = _get_ckids(connection) if collect_CKIDs else []

        connection.disconnect()

        return {
            "hostname": h_name,
            "router_id": router_id,
            "chassis": chassis,
            "ios_ver": ios_ver,
            "rom_version": rom_version,
            "ring_if1": {
                "if_id": ring_ports[0],
                "if_ip": if1_ip,
                "neighbor": if1_neighbor,
            },
            "ring_if2": {
                "if_id": ring_ports[1],
                "if_ip": if2_ip,
                "neighbor": if2_neighbor,
            },
            "ckid_list": circuit_ids,
        }

    except Exception as e:
        print(e)
        return None


def _xr_get_device_info(connection, ring_id, template_dir):
    """Gets device information for Cisco XR devices."""

    # Set textfsm template paths
    if_desc_tmpl_file = Path("cisco_xr_show_interfaces_description.textfsm")
    if_desc_tmpl_path = str(template_dir / if_desc_tmpl_file)

    # Send commands and parse output
    h_name = connection.find_prompt()[:-1].split(":")[1]
    dev_id_out = connection.send_command("show router-id")
    platform = connection.send_command("admin show platform")
    version = connection.send_command("show version")
    if_desc_output = connection.send_command(
        "show interfaces description",
        use_textfsm=True,
        textfsm_template=if_desc_tmpl_path
    )

    return (h_name, dev_id_out, platform, version, if_desc_output)


def _xr_parse_device_info(dev_id_out, platform, version, if_desc_output, ring_id, collect_CKIDs=True):
    """Parses device information for Cisco XR devices."""

    # Define and compile regex patterns
    chassis_pattern = re.compile(r"(N540X?-[A26][C8Z][CZ1][48]?[CG]?-SYS-?[AD]?)")
    version_pattern = re.compile(r"(?:\s+Version\s+\:\s)(\d\.\d\.\d)")
    ip_regex = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    # Compile the regex for service descriptions
    serv_des_re = re.compile(
        r"(?P<aloc>[A-Z]{6}\w{2})/"
        r"(?P<circuitid>[A-Z]{3}\w{3})/"
        r"(?P<zloc>[A-Z]{6}\w{2})[-_]"
        r"(?P<bandwidth>\d{1,5}M)[-_]"
        r"(?P<actname>\S+)"
    )

    # Parse device information
    dev_id_match = ip_regex.findall(dev_id_out)
    if len(dev_id_match) != 1:
        print(dev_id_match)
        raise ValueError("Invalid router ID output.")

    chassis = chassis_pattern.search(platform)[1]
    ios_ver = version_pattern.search(version)[1]

    # Initialize lists and flags
    ring_ports = []
    service_ports = []  # Will remain empty if collect_CKIDs is False
    dia_circuit = False
    epl_circuit = False
    ela_circuit = False
    voice_circuit = False

    # Process each interface entry if it has a non-empty description.
    for if_line in if_desc_output:
        description = if_line.get("description", "")
        if not description:
            continue

        # Skip management interfaces
        if description == "MGT_UPS":
            continue

        # Check if the interface belongs to the ring
        if ring_id in description:
            ring_ports.append(if_line["interface"])
        else:
            # If we're collecting CKIDs, process the service interface data.
            if collect_CKIDs:
                service_ports.append(if_line["interface"])
                match = serv_des_re.search(description)
                if match:
                    circuitid = match.group("circuitid")
                    if circuitid.startswith("EIA") or circuitid.startswith("DIA"):
                        dia_circuit = True
                    elif any(circuitid.startswith(x) for x in ["EPL", "EPH", "UNP", "EVC"]):
                        epl_circuit = True
                    elif circuitid.startswith("ELA"):
                        ela_circuit = True
                else:
                    # If the regex doesn't match, assume this is a voice service.
                    voice_circuit = True

    # Validate that exactly two ring ports were found.
    if len(ring_ports) != 2:
        raise ValueError("Device is either not on a ring or interface descriptions don't match.")

    return (dev_id_match[0], chassis, ios_ver, ring_ports, service_ports, dia_circuit, epl_circuit, ela_circuit, voice_circuit)


def _xr_get_interface_info(connection, ring_ports, ip_if_cmd, ospf_ne_cmd):
    """Gets interface information for Cisco XR devices."""

    ring_if1 = ring_ports[0]
    ring_if2 = ring_ports[1]

    if_ip_out1 = connection.send_command(f"{ip_if_cmd} {ring_if1} brief")
    ospf_ne_out1 = connection.send_command(f"{ospf_ne_cmd} {ring_if1}")
    if_ip_out2 = connection.send_command(f"{ip_if_cmd} {ring_if2} brief")
    ospf_ne_out2 = connection.send_command(f"{ospf_ne_cmd} {ring_if2}")

    return (if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2)


def _xr_parse_interface_info(if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2):
    """Parses interface information for Cisco XR devices."""

    ip_regex = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

    if1_ip = ip_regex.findall(if_ip_out1)
    if len(if1_ip) != 1:
        raise ValueError("Invalid interface 1 IP output.")
    if1_neighbor = ip_regex.findall(ospf_ne_out1)
    if len(if1_neighbor) != 2:
        raise ValueError("Invalid interface 1 neighbor output.")

    if2_ip = ip_regex.findall(if_ip_out2)
    if len(if2_ip) != 1:
        raise ValueError("Invalid interface 2 IP output.")
    if2_neighbor = ip_regex.findall(ospf_ne_out2)
    if len(if2_neighbor) != 2:
        raise ValueError("Invalid interface 2 neighbor output.")

    return (if1_ip[0], if1_neighbor[0], if2_ip[0], if2_neighbor[0])


def xr_device_info(connection, ring_id, template_dir, collect_CKIDs=True):
    """Gets device information for Cisco XR devices."""

    ip_if_cmd = "show ip interface"
    ospf_ne_cmd = "show ip ospf neighbor"

    try:
        connection.establish_connection()

        h_name, dev_id_out, platform, version, if_desc_output = \
            _xr_get_device_info(connection, ring_id, template_dir)

        router_id, chassis, ios_ver, ring_ports, service_ports, \
            dia_circuit, epl_circuit, ela_circuit, voice_circuit = \
            _xr_parse_device_info(dev_id_out, platform, version, \
                if_desc_output, ring_id, collect_CKIDs)
        print(f"Service Ports: {service_ports}")
        print(f"DIA: {dia_circuit}")
        print(f"EPL: {epl_circuit}")
        print(f"ELA: {ela_circuit}")
        print(f"Voice: {voice_circuit}")

        if1_ip, if1_neighbor, if2_ip, if2_neighbor = \
            _xr_parse_interface_info(*_xr_get_interface_info(connection, ring_ports, ip_if_cmd, ospf_ne_cmd))

        circuit_ids = _get_ckids(connection) if collect_CKIDs else []

        connection.disconnect()

        return {
            "hostname": h_name,
            "router_id": router_id,
            "chassis": chassis,
            "ios_ver": ios_ver,
            "rom_version": None,
            "ring_if1": {
                "if_id": ring_ports[0],
                "if_ip": if1_ip,
                "neighbor": if1_neighbor,
            },
            "ring_if2": {
                "if_id": ring_ports[1],
                "if_ip": if2_ip,
                "neighbor": if2_neighbor,
            },
            "ckid_list": circuit_ids,
        }

    except Exception as e:
        print(e)
        return None

def _get_device_info(connection, ios_type, ring_id, templates_dir, collect_CKIDs):
    """Gets device information based on IOS type."""
    try:
        if ios_type == "cisco_xe":
            return xe_device_info(connection, ring_id, templates_dir, collect_CKIDs)
        elif ios_type == "cisco_xr":
            return xr_device_info(connection, ring_id, templates_dir, collect_CKIDs)
        else:
            return None
    except Exception as e:
        print(e)
        return None


def _determine_next_router(device_info, previous_router, agg_router01, agg_router02, core_ips, router):
    """Determines the next router to connect to."""

    if not previous_router:
        return (
            device_info['ring_if2']['neighbor']
            if device_info
            and device_info['ring_if1']['neighbor'] == agg_router02
            else device_info['ring_if1']['neighbor'] if device_info else None
        )

    elif device_info and device_info['ring_if1']['neighbor'] == previous_router:
        return (
            None
            if (
                router not in core_ips
                and device_info['ring_if2']['neighbor'] == agg_router01
            )
            or router in core_ips
            else device_info['ring_if2']['neighbor']
        )
    elif (router not in core_ips and device_info and device_info['ring_if1']['neighbor'] == agg_router01) or router in core_ips:
        return None

    elif device_info:
        return device_info['ring_if1']['neighbor']
    else:
        return None


def _walk_ring(router, previous_router, agg_router01, agg_router02, ring_id, templates_dir, core_ips):
    """Walks the ring and gathers device information."""

    dev_count = 0
    all_dev_info = []
    ckid_full_list = []

    router = agg_router01

    while router:  # Loop until no next router is found
        collect_CKIDs = router not in core_ips
        if collect_CKIDs:
            dev_count += 1

        print("Figuring out device type and setting up connection...")
        ios_type = guess_dev_type(router)
        connection = device_connect(router, ios_type)
        print(f"Gathering device information ({router})...")

        device_info = _get_device_info(connection, ios_type, ring_id, templates_dir, collect_CKIDs)

        if device_info:
            if device_info['ckid_list']:
                ckid_full_list.extend(device_info.pop('ckid_list'))
            all_dev_info.append(device_info)
            print_device_info(device_info)

        next_router = _determine_next_router(device_info, previous_router, agg_router01, agg_router02, core_ips, router)
        previous_router = router
        router = next_router

    return all_dev_info, ckid_full_list, dev_count


def print_device_info(device_info):
    """Prints formatted device information."""
    if not device_info:
        return

    formatted_info = f"{device_info['hostname']} - " \
                     f"{device_info['router_id']} - " \
                     f"{device_info['chassis']} - " \
                     f"{device_info['ios_ver']} - "

    if device_info['rom_version']:
        formatted_info += f"{device_info['rom_version']}"
        if "901" in device_info['chassis'] \
            or "903" in device_info['chassis']:
            print_red(formatted_info)
        elif device_info['ios_ver'] != "16.12.6" \
        or device_info['rom_version'] != "15.6(48r)S":
            print_yellow(formatted_info)
        else:
            print(formatted_info)
    elif device_info['ios_ver'] != "7.7.21":
        print_yellow(formatted_info)
    else:
        print(formatted_info)


def save_data(save_directory, ring_id, all_dev_info, ckid_full_list):
    """Saves the collected data to files."""

    print(f"Creating and saving files to: {save_directory}")
    dev_file_path = save_directory / Path(f"Dev_Info_{ring_id}.json")
    ckid_file_path = save_directory / Path(f"CKIDs_{ring_id}.txt")

    with dev_file_path.open('w') as f:
        json.dump(all_dev_info, f, indent=4)

    with open(ckid_file_path, 'w') as f:
        for item in ckid_full_list:
            f.write(item + "\n")

    print("Circuit IDs:")
    for each_id in ckid_full_list:
        print(each_id)


def main():
    global username
    global password

    print("Enter your username:")
    username = input("Username: ")
    print("Enter your password:")
    password = getpass()

    core_ips = get_core_router_ips()
    ring_id = get_ring_id()

    spec = find_spec("ntc_templates")
    templates_dir = Path(spec.submodule_search_locations[0]) / Path("templates")

    agg_router01 = core_ips[0]
    agg_router02 = core_ips[1] or core_ips[0]

    print("Dual Hub Ring" if core_ips[1] else "Single Hub Ring")
    print(f"Agg 1: {agg_router01}")
    if core_ips[1]:
        print(f"Agg 2: {agg_router02}")

    input("Press enter to open a dialog box and choose a folder for saving device and circuit ID files...")
    save_directory = Path(get_dir_path())

    start_time = datetime.now()

    print(f"Attempting to walk {ring_id} starting at {agg_router01}...")

    all_dev_info, ckid_full_list, dev_count = _walk_ring(
        None, None, agg_router01, agg_router02, ring_id, templates_dir, core_ips
    )

    save_data(save_directory, ring_id, all_dev_info, ckid_full_list)

    print(f"Number of devices on ring: {dev_count}")
    print("\n\nTime taken: ", datetime.now() - start_time)


if __name__ == "__main__":
    main()
