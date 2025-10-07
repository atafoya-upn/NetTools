#!/usr/bin/python3

###############################################################################
#   FULL_CONFIGS.py Ver 2.0                                                   #
#   Author: Adam Tafoya                                                       #
#   Contributions: Scott Hensley                                              #
#   Date: October 2025                                                        #
#                                                                             #
# Dependencies:                                                               # 
#   Python3.9 or higher                                                       #
#   pandas                                                                    #
#   mechanicalsoup                                                            #
#   urllib3                                                                   #
#                                                                             #
# Script Description:                                                         #
#   This Python script is used to read the excel doc produced by              #
#   RING_CONV_PREP_NOVISIO.py, connect to engineering toolbox, and create     #
#   full configs for each device on the ring. You will still need to review   #
#   these configs before applying them to the devices.                        #
#                                                                             #
#   The script will prompt you to select the directory where the ring data    #
#   spreadsheet is located. The ring ID will be determined from the name of   #
#   the directory. A sub-directory named 'Configs' will be created to store   #
#   the generated configs.                                                    #
#                                                                             #
#   The script will also prompt you to specify if the ring terminates on one  #
#   or two aggregation routers. This is needed to properly handle the data in #
#   the spreadsheet.                                                          #
#                                                                             #
#   The script will read the ring data spreadsheet and remove the aggregation #
#   router rows. It will then log into the engineering toolbox using the      #
#   provided credentials, and generate configurations for each device on the  #
#   ring based on the chassis type and other parameters. The generated        #
#   configs will be saved as text files in the 'Configs' sub-directory.       #
#                                                                             #
#   Note: The script disables SSL verification warnings for simplicity.       #
#                                                                             #
# Usage:                                                                      #
#   1. Ensure you have Python 3.9 or higher installed.                        #
#   2. Install the required packages: pandas, mechanicalsoup, python-dotenv   #
#      You can install them using pip:                                        #
#      pip install pandas mechanicalsoup python-dotenv                        #
#   3. Create a .env file in the same directory as this script with the       #
#      following keys:                                                        #
#      TB_LOGIN_URL=<engineering_toolbox_login_url>                           #
#      TB_CONFGEN_URL=<your_toolbox_confgen_url>                              #
#      (Optional) TB_USERNAME=<your_username>                                 #
#      (Optional) TB_PASSWORD=<your_password>                                 #
#   4. Run the script:                                                        #
#      python FULL_CONFIGS.py                                                 #
#   5. Follow the prompts to select the directory and specify ring            #
#      termination.                                                           #
#   6. Review the generated configs in the 'Configs' sub-directory.           #
#                                                                             #
# Important:                                                                  #
#   - Ensure that the URLs in the .env file are correct and accessible.       #
#   - Review the generated configs before applying them to the devices.       #
###############################################################################

import urllib3
from urllib3.exceptions import InsecureRequestWarning
import sys
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
from typing import Optional, Tuple
from urllib.parse import urlparse
import subprocess
from importlib.util import find_spec
from importlib import metadata


# Ensure required packages are installed
# Map: import_name -> pip_name
REQUIRED_PACKAGES = {
    "dotenv": "python-dotenv",
    "pandas": "pandas",
    "mechanicalsoup": "MechanicalSoup",
}

def _is_installed(import_name: str) -> bool:
    return find_spec(import_name) is not None


def _installed_version(pip_name: str) -> str:
    try:
        return metadata.version(pip_name)
    except metadata.PackageNotFoundError:
        return ""


def _pip_install(*args: str) -> int:
    # Use the same interpreter that's running this script
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    cmd += list(args)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Print output only on non-zero exit to aid debugging
    if proc.returncode != 0:
        print(proc.stdout)
    return proc.returncode


def ensure_dependencies(requirements: dict = REQUIRED_PACKAGES) -> None:
    missing = [imp for imp in requirements if not _is_installed(imp)]
    if not missing:
        return
    # Install missing by their pip names
    to_install = [requirements[imp] for imp in missing]
    rc = _pip_install(*to_install)
    if rc != 0:
        raise SystemExit(
            "Failed to install required packages: "
            + ", ".join(to_install)
            + "\nTip: run with admin/venv privileges or install manually using:\n"
            + f"{sys.executable} -m pip install " + " ".join(to_install)
        )
    # Verify imports now work
    still_missing = [imp for imp in requirements if not _is_installed(imp)]
    if still_missing:
        details = []
        for imp in still_missing:
            pipn = requirements[imp]
            details.append(f"{imp} (pip name: {pipn}, version seen: '{_installed_version(pipn) or 'not found'}')")
        raise SystemExit(
            "Packages were installed but imports still failed (interpreter mismatch?).\n"
            + "\n".join(details)
            + "\nMake sure you installed into the SAME interpreter:\n"
            + f"{sys.executable} -m pip show python-dotenv pandas mechanicalsoup"
        )


def load_env() -> None:
    """Load environment from .env if present."""
    load_dotenv()


def _env_str(key: str) -> Optional[str]:
    v = os.getenv(key)
    return v.strip() if v and v.strip() else None


def _is_http_url(s: str) -> bool:
    try:
        u = urlparse(s)
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False


def resolve_toolbox_urls(require_env: bool = True) -> Tuple[str, str]:
    """
    Read TB_LOGIN_URL and TB_CONFGEN_URL from .env.
    If require_env is True (default), exit with a clear message if missing/invalid.
    """
    login_url = _env_str("TB_LOGIN_URL")
    conf_url  = _env_str("TB_CONFGEN_URL")

    missing = []
    if not login_url:
        missing.append("TB_LOGIN_URL")
    if not conf_url:
        missing.append("TB_CONFGEN_URL")

    if require_env and missing:
        raise SystemExit(
            "Missing required keys in .env: "
            + ", ".join(missing)
            + "\nAdd them to keep the private server addresses out of the code."
        )

    if login_url and not _is_http_url(login_url):
        raise SystemExit("TB_LOGIN_URL must be a valid http(s) URL.")
    if conf_url and not _is_http_url(conf_url):
        raise SystemExit("TB_CONFGEN_URL must be a valid http(s) URL.")

    return login_url, conf_url


def getCredentials(defaultUser, credTitle):
    """Request login credentials using a GUI"""
    print("Entering GUI to get username and password...")
    # Create the main window
    root = tk.Tk()
    root.title(credTitle)
    root.attributes('-topmost', True)
    # Window size
    window_width = 300
    window_height = 150
    # Get the screen dimensions
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    # Calculate the position to center the window
    center_x = int(screen_width/2 - window_width / 2)
    center_y = int(screen_height/2 - window_height / 2)
    # Set the size and position of the window
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    root.resizable(False, False)
    # Define StringVar for username and password
    userVar = tk.StringVar(root, value=defaultUser)
    passVar = tk.StringVar(root, value='')
    # Create frame for username with label and entry box
    userFrame = tk.Frame(root, padx=10, pady=2)
    userFrame.pack(side=tk.TOP)
    userLabel = tk.Label(userFrame, text="Username", font=('calibri', 10, 'bold'))
    userLabel.pack(anchor=tk.W)
    userEntry = tk.Entry(userFrame, bd=3, width=40, textvariable=userVar)
    userEntry.pack(anchor=tk.W)
    # Create frame for password with label and entry box
    passFrame = tk.Frame(root, padx=10, pady=2)
    passFrame.pack(side=tk.TOP)
    passLabel = tk.Label(passFrame, text="Password", font=('calibri', 10, 'bold'))
    passLabel.pack(anchor=tk.W)
    passEntry = tk.Entry(passFrame, bd=3, width=40, show="*", textvariable=passVar)
    passEntry.pack(anchor=tk.W)
    # Create submit button and position at bottom right
    btnClose = tk.Button(root, text="Submit", command=root.destroy)
    btnClose.pack(padx=10, pady=10, side=tk.BOTTOM, anchor=tk.SE)
    # Run the GUI event loop
    root.mainloop()
    # Return the entered username and password
    return [userVar.get(), passVar.get()]


def resolve_toolbox_credentials(
    getCredentials_func,
    default_username: str = "admin",
    dialog_title: str = "Toolbox Login Credentials",
) -> Tuple[str, str]:
    """
    If both TB_USERNAME and TB_PASSWORD exist in .env, return them.
    Otherwise call your GUI getCredentials(default_user, title).
    - If only TB_USERNAME exists, it becomes the default shown in the GUI.
    - If neither exists, 'admin' is shown as the default.
    """
    env_user = _env_str("TB_USERNAME")
    env_pass = _env_str("TB_PASSWORD")

    if env_user and env_pass:
        return env_user, env_pass

    default_user = env_user if env_user else default_username
    user, pw = getCredentials_func(default_user, dialog_title)
    if not user or not pw:
        raise SystemExit("Credentials not provided. Aborting.")
    return user.strip(), pw


def get_dir_path():
    """
    Prompts the user to select a directory using a file dialog.

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


def loginTB(browser, tbUser, tbPass, loginUrl):
    # Open browser and login to toolbox
    browser.open(loginUrl, verify=False)
    browser.select_form()
    # Fill in login credentials and submit
    browser["username"] = tbUser
    browser["password"] = tbPass
    browser.submit_selected(verify=False)


def enternode(browser, sr_ring, device, host_name, sr_ip, confgenUrl):
    # Open the SR router configuration generator page
    browser.open(confgenUrl, verify=False)
    # Fill in the form with the provided parameters
    browser.select_form()
    browser['ringid'] = sr_ring
    browser['template'] = device
    browser['hostname'] = host_name
    browser['loopbackip'] = sr_ip
    browser.submit_selected(verify=False)
    # Select the form again to access the generated configuration
    browser.select_form()
    # Select the textarea containing the configuration
    config = browser.page.find("textarea", attrs={"class": "form-control"}).text
    return config


def remove_end(config):
    # Remove 'end' from the configuration string if it exists
    if config.endswith('\nend\n'):
        config = config[:-4]  # Remove the last 4 characters ('end\n')
    return config


def writeconfig(host_name, baseconfig, serviceconfig):
    # Write the configuration to a text file named with the hostname
    with open(f'{host_name}.txt', 'w') as f:
        f.write(baseconfig + serviceconfig)


def main():
    # Load environment variables
    load_env()
    # Read the private URLs (required from .env)
    tb_login_url, tb_confgen_url = resolve_toolbox_urls()
    # Resolve credentials (env → GUI fallback)
    tb_username, tb_password = resolve_toolbox_credentials(getCredentials)
    # Disable the InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
    # Set up the browser object
    browser = mechanicalsoup.StatefulBrowser()
    # Set directory path
    input("Press enter to open a dialog box and choose the directory where the ring data spreadsheet is located...")
    ring_directory = Path(get_dir_path())
    sr_ring = os.path.basename(os.path.normpath(ring_directory))
    ring_data_file = ring_directory / f'{sr_ring}_configs.xlsx'
    conf_dir = ring_directory / 'Configs'
    if ring_data_file.exists():
        print(f'{sr_ring} data file found\n')
    else:
        print('You need to create ring data file')
    if conf_dir.exists():
        print('router config directory already exists. \n')
    else:
        os.mkdir(conf_dir)
        print('router config directory created\n')
    # Determine if ring terminates on one or two aggregation routers
    agg_router_count = input('Does this ring terminate on one or two aggregation routers? (Enter 1 or 2): ')
    while agg_router_count not in ['1', '2']:
        print("Invalid input. Please enter '1' or '2'.")
        agg_router_count = input('Does this ring terminate on one or two aggregation routers? (Enter 1 or 2): ')
    agg_router_count = int(agg_router_count)
    # Load data from the spreadsheet and remove aggregation router rows
    df_ring_hosts = pd.read_excel(ring_data_file, sheet_name='Devices', usecols='A,C,D')
    df_service_configs = pd.read_excel(ring_data_file, sheet_name='Service_Configs', usecols='D')
    if agg_router_count == 1:
        df_ring_hosts.drop(df_ring_hosts.index[0], inplace=True)
        df_service_configs.drop(index=df_service_configs.index[0], inplace=True)
    else:
        df_ring_hosts.drop(index=[df_ring_hosts.index[0], df_ring_hosts.index[-1]], inplace=True)
        df_service_configs.drop(index=[df_service_configs.index[0], df_service_configs.index[-1]], inplace=True)
    # Reset index after dropping rows
    df_ring_hosts.reset_index(drop=True, inplace=True)
    df_service_configs.reset_index(drop=True, inplace=True)
    # Get chassis information and map to templates
    devices = df_ring_hosts['Chassis'].values.tolist()
    service_configs = df_service_configs['Z_Config'].values.tolist()
    # Chassis index for choosing template in toolbox
    asr_920_12 = ['A901-6CZ-F-A', 'A901-6CZ-F-D', 'ASR-920-12CZ-A', 'ASR-920-12CZ-D','ASR-920-24SZ-M']
    asr_920_4 = ['ASR-920-4SZ-D', 'ASR-920-4SZ-A']
    n540X = ['N540X-6Z18G-SYS-D', 'N540X-6Z18G-SYS-A']
    n540_28 = ['N540-28Z4C-SYS-D', 'N540-28Z4C-SYS-A']
    ncs540 = ['NCS-540']
    r_templates = ['ASR920-12CZ 10Gig Ring', 'ASR920-4SZ 10Gig Ring',
                'NCS540X-6Z18G 10Gig Ring', 'NCS540-ACC-SYS 100Gig Ring',
                'NCS540-28Z4C 100Gig Ring']
    # Choose template based on chassis type
    for d in devices:
        if d in asr_920_12:
            i = devices.index(d)
            devices[i] = r_templates[0]
        if d in asr_920_4:
            i = devices.index(d)
            devices[i] = r_templates[1]
        if d in n540X:
            i = devices.index(d)
            devices[i] = r_templates[2]
        if d in n540_28:
            i = devices.index(d)
            devices[i] = r_templates[4]
        if d in ncs540:
            i = devices.index(d)
            devices[i] = r_templates[3]
    # Update chassis column with template names
    df_ring_hosts['Chassis'] = pd.Series(devices)
    # Log into engineering toolbox
    loginTB(browser, tb_username, tb_password, tb_login_url)
    # Change to configuration directory
    os.chdir(conf_dir)
    # Generate configurations for each device
    for n in range(len(df_ring_hosts)):
        dName = df_ring_hosts.iloc[n, 0]
        dtype = df_ring_hosts.iloc[n, 2]
        newIP = df_ring_hosts.iloc[n, 1]
        print(f'Generating config for {dName} - {dtype} - {newIP}')
        baseconfig = enternode(browser, sr_ring, dtype, dName, newIP, tb_confgen_url)
        # Removes 'end' from the base configuration string in 540 configs
        mod_baseconfig = remove_end(baseconfig)
        # Write the full configuration to a text file
        writeconfig(dName, mod_baseconfig, service_configs[n])


if __name__ == "__main__":
    # Ensure python 3.9 or higher is installed
    if sys.version_info.major != 3 and sys.version_info.minor >= 9:
        print(
            "Your Python version is outdated and may not be compatible with this "
            "script."
        )
        print("Please consider updating Python to version 3.9 or later.")
        print(
            "You can download the latest version from: "
            "https://www.python.org/downloads/"
        )
        sys.exit(1)
    ensure_dependencies()  # ensures dotenv, pandas, mechanicalsoup exist
    from dotenv import load_dotenv
    import pandas as pd
    import mechanicalsoup
    raise SystemExit(main())