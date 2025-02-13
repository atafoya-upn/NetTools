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
#   port interface IDs, P2P IPs on the ring ports, neighbor IDs on the ring   #
#   ports, and service configs. It also gathers CKIDs for all services on     #
#   each device except for the core/aggregate routers. Some information is    #
#   output regularly so the user doesn't assume the script stopped running as #
#   it can take up to 20 minutes or so for this script to complete on larger  #
#   rings. Two files will be created with all the collected data sorted. The  #
#   script will prompt you for a specific directory where the files will be   #
#   saved. Devices will be listed in the order that they appear on the ring.  #
#   The following file will be saved to the save directory:                   # 
#   {ring_id}_Dev_Info.json                                                   #
#   {ring_id}_configs.xlsx                                                    #
#   The json has much of the same info but I plan to use it for creating      #
#   a network drawing of the ring through another script.                     #
#                                                                             #
# To do:                                                                      #
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
import pandas as pd

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
        elif collect_CKIDs:
            service_ports.append(if_line["port"])
            if match := serv_des_re.search(description):
                circuitid = match["circuitid"]
                if circuitid.startswith("EIA") or circuitid.startswith("DIA"):
                    dia_circuit = True
                elif any(circuitid.startswith(x) for x in ["EPL", "EPH", "UNP", "EVC"]):
                    epl_circuit = True
                elif circuitid.startswith("ELA"):
                    ela_circuit = True
            else:
                # If the regex doesn't match, assume this is a voice service.
                voice_circuit = True

    # Validate that at least one ring port was found.
    if not ring_ports:
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


def _xe_get_service_conf(connection, service_ports, dia_circuit, epl_circuit, ela_circuit, voice_circuit):
    """Gets service configurations for Cisco XE devices."""

    service_configs = "!\n"
    service_configs += _xe_get_voice_configs(connection, voice_circuit)
    service_configs += _xe_get_cfm_configs(connection, epl_circuit)
    service_configs += _xe_get_l2vpn_configs(connection, ela_circuit, service_ports)
    service_configs += _xe_get_interface_and_policy_map_configs(connection, service_ports)

    return service_configs


def _xe_get_voice_configs(connection, voice_circuit):
    """Gets voice-related configurations."""
    if not voice_circuit:
        return ""

    vrf_out = connection.send_command("show run | s ip vrf VOICE").splitlines()
    bgp_out = f"!\n{connection.send_command('sh run vrf VOICE | s router bgp')}"
    bgp_split = bgp_out.splitlines()

    voice_configs = "".join(f"{line}\n" for line in vrf_out)
    for line in bgp_split:
        voice_configs += f"{line}\n"

    return voice_configs


def _xe_get_cfm_configs(connection, epl_circuit):
    """Gets CFM configurations."""

    if not epl_circuit:
        return ""

    cfm_out = connection.send_command("show run | s ethernet cfm").splitlines()
    evc_out = connection.send_command("show run | i ethernet evc").splitlines()

    cfm_configs = "".join(f"{line}\n" for line in cfm_out)
    for line in evc_out:
        cfm_configs += f"{line}\n"
    return cfm_configs


def _xe_get_l2vpn_configs(connection, ela_circuit, service_ports):
    """Gets L2VPN configurations."""

    if not ela_circuit:
        return ""

    l2vpn_configs = ""
    bd_re = re.compile(r"\s*(\d+)\s+")
    vfi_re = re.compile(r"member\s+vfi\s+([A-Za-z0-9_-]+)")

    for port in service_ports:
        port_desc = connection.send_command(f"show interface {port} description")
        if "ELA" in port_desc:
            port_conf = connection.send_command(f"show bridge-domain | i {port}")
            if bd_number_search := bd_re.search(port_conf):
                bd_number = bd_number_search[1]
            bridge_dom_output = connection.send_command(
                f"show run | s bridge-domain {bd_number}"
            ).splitlines()
            if vfi_name_match := vfi_re.search("\n".join(bridge_dom_output)):
                vfi_name = vfi_name_match[1]
                vfi_out = connection.send_command(
                    f"show run | s l2vpn vfi context {vfi_name}"
                ).splitlines()

                for line in vfi_out:
                    l2vpn_configs += f"{line}\n"
                for line in bridge_dom_output:
                    l2vpn_configs += f"{line}\n"

    return l2vpn_configs


def _xe_get_interface_and_policy_map_configs(connection, service_ports):
    """Gets interface and policy map configurations."""

    p_map_re = re.compile(r"(?:service-policy \w{2,3}put )([SP]\d{1,5}M)")
    configs = ""
    if_configs = ""
    p_map_configs = ""

    for port in service_ports:
        if_config = connection.send_command(f"show run interface {port}")
        if_conf_split = if_config.splitlines()[3:-1]
        for line in if_conf_split:
            if_configs += f"{line}\n"
        for p_map in p_map_re.findall(if_config):
            p_map_out = connection.send_command(f"show run policy-map {p_map}")
            p_map_split = p_map_out.splitlines()[3:-1]
            for line in p_map_split:
                p_map_configs += f"{line}\n"
        
    return p_map_configs + if_configs

def _xe_get_interface_info(connection, ring_ports):
    """Gets interface information for Cisco XE devices."""

    ip_if_cmd = "show ip interface brief"
    ospf_ne_cmd = "show ip ospf neighbor"

    ring_if1 = ring_ports[0]
    if_ip_out1 = connection.send_command(f"{ip_if_cmd} {ring_if1}")
    ospf_ne_out1 = connection.send_command(f"{ospf_ne_cmd} {ring_if1}")
    if len(ring_ports) != 2:
        if_ip_out2 = None
        ospf_ne_out2 = None
    else:
        ring_if2 = ring_ports[1]
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

    if1_ip = ip_regex.findall(if_ip_out1)[0]
    if1_neighbor = ip_regex.findall(ospf_ne_out1)[0]
    if if_ip_out2:
        if2_ip = ip_regex.findall(if_ip_out2)[0]
        if2_neighbor = ip_regex.findall(ospf_ne_out2)[0]
    else:
        if2_ip = None
        if2_neighbor = None

    return (dev_id_match[0], if1_ip, if1_neighbor, if2_ip, if2_neighbor)


def xe_device_info(connection, ring_id, template_dir, collect_CKIDs=True):
    """Gets device information for Cisco XE devices."""

    try:
        connection.establish_connection()

        h_name, outputs = _xe_get_device_info(connection, ring_id, template_dir)
        chassis, ios_ver, rom_version, ring_ports, service_ports, \
            dia_circuit, epl_circuit, ela_circuit, voice_circuit = \
                _xe_parse_device_info(outputs, ring_id, collect_CKIDs)
        router_id, if1_ip, if1_neighbor, if2_ip, if2_neighbor = \
            _xe_parse_interface_info(*_xe_get_interface_info(connection, ring_ports))
        service_configs = _xe_get_service_conf(connection, service_ports, \
            dia_circuit, epl_circuit, ela_circuit, voice_circuit)
        circuit_ids = _get_ckids(connection) if collect_CKIDs else []

        connection.disconnect()

        ring_port2 = None if len(ring_ports) != 2 else ring_ports[1]
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
                "if_id": ring_port2,
                "if_ip": if2_ip,
                "neighbor": if2_neighbor,
            },
            "service_configs": service_configs,
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
    version_pattern = re.compile(r"(?:\s+Version\s+\:\s)(\d\.\d\.\d+)")
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
        elif collect_CKIDs:
            service_ports.append(if_line["interface"])
            if match := serv_des_re.search(description):
                circuitid = match["circuitid"]
                if circuitid.startswith("EIA") or circuitid.startswith("DIA"):
                    dia_circuit = True
                elif any(circuitid.startswith(x) for x in ["EPL", "EPH", "UNP", "EVC"]):
                    epl_circuit = True
                elif circuitid.startswith("ELA"):
                    ela_circuit = True
            else:
                # If the regex doesn't match, assume this is a voice service.
                voice_circuit = True

    # Validate that no less than one ring port was found.
    if not ring_ports:
        raise ValueError("Device is either not on a ring or interface descriptions don't match.")

    return (dev_id_match[0], chassis, ios_ver, ring_ports, service_ports, dia_circuit, epl_circuit, ela_circuit, voice_circuit)


def _xr_get_service_conf(connection, service_ports, dia_circuit, epl_circuit, ela_circuit, voice_circuit):
    """Gets service configurations for Cisco XR devices."""

    service_configs = "!\n"
    service_configs += _xr_get_cfm_configs(connection, epl_circuit)
    service_configs += _xr_get_interface_and_policy_map_configs(connection, service_ports)
    service_configs += _xr_get_l2vpn_configs(connection, dia_circuit, epl_circuit, ela_circuit, service_ports)
    service_configs += _xr_get_voice_configs(connection, voice_circuit)

    return service_configs


def _xr_get_interface_and_policy_map_configs(connection, service_ports):
    """Gets policy-map configurations."""

    p_map_re = re.compile(r"(?:service-policy \w{2,3}put )([SP]\d{1,5}M)")
    p_map_configs = ""
    interface_configs = ""

    for port in service_ports:
        if_config = connection.send_command(f"show run interface {port}")
        for p_map in p_map_re.findall(if_config):
            p_map_out = connection.send_command(f"show run policy-map {p_map}").splitlines()[2:-1]
            for line in p_map_out:
                p_map_configs += f"{line}\n"
            for line in if_config.splitlines()[2:-1]:
                interface_configs += f"{line}\n"

    return p_map_configs + interface_configs


def _xr_get_l2vpn_configs(connection, dia_circuit, epl_circuit, ela_circuit, service_ports):
    """Gets L2VPN configurations."""

    l2vpn_configs = ""

    if dia_circuit:
        l2vpn_configs += _get_xr_config_section(connection, "show run l2vpn xconnect group DIA")
    if epl_circuit:
        l2vpn_out = connection.send_command("show run l2vpn xconnect group EVPL")
        if r"No such configuration item(s)" in l2vpn_out:
            l2vpn_out = connection.send_command("show run l2vpn xconnect group EPL")
        l2vpn_configs += "\n".join(l2vpn_out.splitlines()[2:-1]) + "\n"

    if ela_circuit:
        bd_re = re.compile(r"(?:Bridge group:\s)(?<bgroup>[\w-_]+)(?:, bridge-domain: )(?<bdomain>[\w-_]+)")
        for port in service_ports:
            port_desc = connection.send_command(f"show interface {port} description")
            if "ELA" in port_desc:
                bridge_dom_output = connection.send_command(
                    f"show l2vpn bridge-domain interface {port}"
                )
                if bridge_match := bd_re.search(bridge_dom_output):
                    bridge_group = bridge_match["bgroup"]
                    l2vpn_out = connection.send_command(
                            f"show run l2vpn bridge group {bridge_group}"
                        ).splitlines()[2:-1]
                    l2vpn_configs += "\n".join(l2vpn_out) + "\n"
    return l2vpn_configs


def _xr_get_cfm_configs(connection, epl_circuit):
    """Gets CFM configurations."""
    if not epl_circuit:
        return ""
    return _get_xr_config_section(connection, "show run ethernet cfm domain UPN_L3 level 3")


def _xr_get_voice_configs(connection, voice_circuit):
    """Gets voice-related configurations."""

    voice_configs = ""
    if voice_circuit:
        voice_configs += _get_xr_config_section(connection, "show run vrf VOICE")
        voice_configs += _get_xr_config_section(connection, "show run router bgp 15164 vrf VOICE")
    return voice_configs


def _get_xr_config_section(connection, command):
    """Gets a specific configuration section using the provided command."""
    output = connection.send_command(command)
    return "\n".join(output.splitlines()[2:-1]) + "\n"


def _xr_get_interface_info(connection, ring_ports, ip_if_cmd, ospf_ne_cmd):
    """Gets interface information for Cisco XR devices."""

    ring_if1 = ring_ports[0]
    if_ip_out1 = connection.send_command(f"{ip_if_cmd} {ring_if1} brief")
    ospf_ne_out1 = connection.send_command(f"{ospf_ne_cmd} {ring_if1}")
    if len(ring_ports) != 2:
        if_ip_out2 = None
        ospf_ne_out2 = None
    else:
        ring_if2 = ring_ports[1]
        if_ip_out2 = connection.send_command(f"{ip_if_cmd} {ring_if2} brief")
        ospf_ne_out2 = connection.send_command(f"{ospf_ne_cmd} {ring_if2}")
    
    return (if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2)


def _xr_parse_interface_info(if_ip_out1, ospf_ne_out1, if_ip_out2, ospf_ne_out2):
    """Parses interface information for Cisco XR devices."""

    ip_regex = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

    if1_ip = ip_regex.findall(if_ip_out1)[0]
    if1_neighbor = ip_regex.findall(ospf_ne_out1)[0]
    
    if if_ip_out2:
        if2_ip = ip_regex.findall(if_ip_out2)[0]
        if2_neighbor = ip_regex.findall(ospf_ne_out2)[0]
    else:
        if2_ip = None
        if2_neighbor = None

    return (if1_ip, if1_neighbor, if2_ip, if2_neighbor)


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

        service_configs = _xr_get_service_conf(connection, service_ports, dia_circuit, epl_circuit, ela_circuit, voice_circuit)

        if1_ip, if1_neighbor, if2_ip, if2_neighbor = \
            _xr_parse_interface_info(*_xr_get_interface_info(connection, ring_ports, ip_if_cmd, ospf_ne_cmd))

        circuit_ids = _get_ckids(connection) if collect_CKIDs else []

        connection.disconnect()

        ring_port2 = None if len(ring_ports) != 2 else ring_ports[1]
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
                "if_id": ring_port2,
                "if_ip": if2_ip,
                "neighbor": if2_neighbor,
            },
            "service_configs": service_configs,
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
    device_list = []
    ckid_full_list = []
    config_list = []

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
            if device_info['service_configs']:
                conf_row = {
                    "Hostname": device_info['hostname'],
                    "A_Config": "",
                    "A_Device": "",
                    "Z_Config": device_info.pop('service_configs'),
                    "Z_Device": "",
                }
                config_list.append(conf_row)
            dev_row = {
                "Hostname": device_info['hostname'],
                "OLD_IP": device_info['router_id'],
                "SR_IP": "",
                "Chassis": device_info['chassis'],
                "IOS_Version": device_info['ios_ver'],
                "ROM_Version": device_info['rom_version'],
                "Ring_Port1_IP": device_info['ring_if1']['if_ip'],
                "Ring_Port2_IP": device_info['ring_if2']['if_ip'],
            }
            device_list.append(dev_row)
            all_dev_info.append(device_info)
            print_device_info(device_info)

        next_router = _determine_next_router(device_info, previous_router, agg_router01, agg_router02, core_ips, router)
        previous_router = router
        router = next_router

    return all_dev_info, device_list, config_list, ckid_full_list, dev_count


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


def save_data(save_directory, ring_id, all_dev_info, device_list, config_list, ckid_full_list):
    """Saves the collected data to files."""

    print(f"Creating and saving files to: {save_directory}")
    dev_file_path = save_directory / Path(f"{ring_id}_Dev_Info.json")
    excel_file_path = save_directory / Path(f"{ring_id}_configs.xlsx")

    # Create a DataFrame for the Devices sheet
    devices_df = pd.DataFrame(device_list,
                              columns=["Hostname", "OLD_IP", "SR_IP", "Chassis",
                                       "IOS_Version", "ROM_Version", "Ring_Port1_IP", "Ring_Port2_IP"])
    
    # Create a DataFrame for the CKID_List sheet with one column "CircuitID"
    ckid_df = pd.DataFrame(ckid_full_list, columns=["CircuitID"])

    # Create a DataFrame for the Service_Configs sheet
    service_configs_df = pd.DataFrame(config_list, columns=["Hostname", "A_Config",
                                                            "A_Device", "Z_Config", "Z_Device"])
    
    # Write the three sheets to the Excel file using pandas ExcelWriter
    try:
        with pd.ExcelWriter(excel_file_path, engine='openpyxl') as writer:
            devices_df.to_excel(writer, sheet_name="Devices", index=False)
            service_configs_df.to_excel(writer, sheet_name="Service_Configs", index=False)
            ckid_df.to_excel(writer, sheet_name="CKID_List", index=False)
    except Exception as e:
        print("Error", f"Failed to create Excel file:\n{e}")
        return
    
    print("Success", f"Excel file created successfully:\n{excel_file_path}")

    with dev_file_path.open('w') as f:
        json.dump(all_dev_info, f, indent=4)

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

    all_dev_info, device_list, config_list, ckid_full_list, dev_count = _walk_ring(
        None, None, agg_router01, agg_router02, ring_id, templates_dir, core_ips
    )

    save_data(save_directory, ring_id, all_dev_info, device_list, config_list, ckid_full_list)

    print(f"Number of devices on ring: {dev_count}")
    print("\n\nTime taken: ", datetime.now() - start_time)


if __name__ == "__main__":
    main()
