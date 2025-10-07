# NetTools

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Cisco](https://img.shields.io/badge/target-Cisco_IOS--XR%20%7C%20IOS--XE-blue.svg)

---

## 🧩 Overview

**NetTools** is a collection of Python-based automation tools designed to streamline network maintenance, configuration generation, and information gathering across Cisco environments (IOS-XR and IOS-XE).  
These tools are built for a specific production network but can easily be **re-tooled for use in other networks**.  

All sensitive or proprietary information has been **stripped from the scripts** themselves and replaced with environment variable loading via a `.env` file or secure user input, ensuring operational security and adaptability.

---

## 📚 Table of Contents
- [Overview](#-overview)
- [Projects](#-projects)
  - [SR Conversion Prep](#sr-conversion-prep)
  - [Interface Audit (Planned)](#interface-audit-planned)
  - [ELAN Update Utility (Planned)](#elan-update-utility-planned)
- [Environment](#-environment)
- [Usage](#-usage)
- [Contributors](#-contributors)
- [License](#-license)

---

## 🧰 Projects

### [SR Conversion Prep](./SR_Conversion_Prep/README.md)
Automates the process of migrating Metro Ethernet rings from MPLS to Segment Routing (SR).  
It connects to devices, gathers configuration data, outputs structured Excel and JSON files, and generates full router configuration files through integration with the Engineering Toolbox.

**Includes:**
- `RING_CONV_PREP_NOVISIO.py` – Collects device and service data from the ring  
- `FULL_CONFIGS.py` – Builds and merges base + service configurations  
- `.env` sample file with required credentials and URLs  

**Outputs:**
- `{ring_id}_Dev_Info.json`  
- `{ring_id}_configs.xlsx`  
- `Configs/<hostname>.txt`

---

### Interface Audit (Planned)
Planned utility to perform bulk audits of router interface configurations for consistency and compliance.  
Will support automated detection of mismatched descriptions, IP schema validation, and interface status collection.

---

### ELAN Update Utility (Planned)
Future script to assist in **automating the addition of new sites** to existing ELAN configurations.  
It will gather current service instances, verify VLAN/BD assignments, and push standardized updates or export required configuration snippets for review.

---

## 🖥 Environment

- **Operating System:** Windows 10/11  
- **Python Version:** 3.9+  
- **Target Devices:** Cisco IOS-XR and IOS-XE routers  
- **Virtual Environment Recommended:** Yes

Install Python dependencies per project:
```bash
cd <project_directory>
pip install -r requirements.txt
```

---

## 🚀 Usage

Each project directory includes its own **README.md** detailing dependencies, environment variable requirements, and usage steps.

Example:
```bash
cd SR_Conversion_Prep
python RING_CONV_PREP_NOVISIO.py
```

---

## 👨‍💻 Contributors

- **Adam Tafoya**  
- **Scott Hensley**

---

## 🪪 License

This repository is licensed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.

---

© 2025 Adam Tafoya and Contributors. All rights reserved.
