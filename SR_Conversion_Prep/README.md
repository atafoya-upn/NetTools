# SR Conversion Prep

## Overview

**SR Conversion Prep** is a two-part automation toolkit for simplifying and standardizing the migration of Metro Ethernet rings to Segment Routing (SR). It gathers detailed router and service data from production devices, generates structured Excel documentation, and then builds complete configuration files for each router in the ring using the Engineering Toolbox site.

This project includes the following scripts:

- **`RING_CONV_PREP_NOVISIO.py`** – Collects all router and service data from the ring and exports it to Excel and JSON files.
- **`FULL_CONFIGS.py`** – Reads the Excel file, generates base configurations from the Engineering Toolbox, and combines them with existing service configurations to produce full router configuration files.

---

## Workflow

1. **Run `RING_CONV_PREP_NOVISIO.py`:**
   - Provide the IP(s) of the core router(s) and the Ring ID when prompted.
   - The script connects to each router on the ring, gathers device and service information, and saves two files:
     - `{ring_id}_Dev_Info.json`
     - `{ring_id}_configs.xlsx`

2. **Manual Steps:**
   - Open the generated Excel file and **update the SR IPs** for each router.
   - In the **Engineering Toolbox**, manually edit the ring and change the ring type from **“Cisco MPLS/rLFA”** to **“Cisco SR-MPLS/TI-LFA”**.

3. **Run `FULL_CONFIGS.py`:**
   - Select the directory containing the updated Excel file.
   - Specify if the ring terminates on one or two aggregation routers when prompted.
   - The script logs into the Engineering Toolbox, retrieves base configurations, and merges them with the service configurations.
   - The final configuration files are saved as text files in:
     ```
     <ring_directory>\Configs\<hostname>.txt
     ```

---

## Requirements

- **Python:** 3.9 or higher  
- **Dependencies:**  
  ```bash
  pip install netmiko openpyxl pandas mechanicalsoup urllib3 python-dotenv
  ```

---

## Environment Variables (`.env`)

The scripts rely on a `.env` file for credential and URL management. A sample `.env` file is included for reference.

### Device Login Variables (used by `RING_CONV_PREP_NOVISIO.py`)
| Variable | Description | Required |
|-----------|--------------|-----------|
| `DEVICE_USERNAME_PROD` | Username for production device logins | Optional |
| `DEVICE_PASSWORD_PROD` | Password for production device logins | Optional |
| `DEVICE_USERNAME` | Generic device username (fallback) | Optional |
| `DEVICE_PASSWORD` | Generic device password (fallback) | Optional |

> **Note:** If no credentials are found in the `.env` file, you will be prompted to enter them at runtime.

### Engineering Toolbox Variables (used by `FULL_CONFIGS.py`)
| Variable | Description | Required |
|-----------|--------------|-----------|
| `TB_LOGIN_URL` | Login URL for the Engineering Toolbox | **Required** |
| `TB_CONFGEN_URL` | URL for the Configuration Generator page | **Required** |
| `TB_USERNAME` | Engineering Toolbox username | Optional |
| `TB_PASSWORD` | Engineering Toolbox password | Optional |

> If the Toolbox username and password are not provided, the script will prompt for them interactively.

---

## Output Files

After running both scripts, the following files and directories will be created:

| File / Folder | Description |
|----------------|-------------|
| `{ring_id}_Dev_Info.json` | JSON file containing detailed device data |
| `{ring_id}_configs.xlsx` | Excel spreadsheet with device and service info |
| `Configs/` | Directory containing generated router configuration text files |

---

## Example Usage

```bash
# Step 1: Collect ring data
python RING_CONV_PREP_NOVISIO.py

# Step 2: Update SR IPs and change ring type in Engineering Toolbox

# Step 3: Generate full configs
python FULL_CONFIGS.py
```

---

## Notes

- Review all generated configurations before deployment.  
- Ensure Engineering Toolbox URLs in `.env` are correct and accessible.  
- Large rings may take up to 30 minutes to process.  
- The scripts include validation and retry mechanisms for user inputs.

---

## License

This project is licensed under the **MIT License**.

Copyright © 2025 Adam Tafoya and Contributors.
