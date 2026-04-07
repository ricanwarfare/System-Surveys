# System-Surveys

A collection of stealthy, portable, and comprehensive system survey scripts for Windows and Linux. These tools are designed to gather situational awareness and forensic data while minimizing the logging footprint on the target host.

## Purpose

The scripts in this repository are built with a "Living off the Land" (LotL) philosophy:
- **Windows (`win-survey.js`)**: Written in JScript (Windows Script Host) to stay compatible with Windows 7+ and bypass modern PowerShell-specific logging. It uses WMI, Registry (`StdRegProv`), and COM APIs directly to avoid noisy process creation.
- **Linux (`linux-survey.py`)**: Written in Python 3. It utilizes the `procfs` (`/proc`) and `sysfs` (`/sys`) filesystems directly to gather data, ensuring that standard system auditing tools (like `auditd`) see minimal activity.

## Key Features

### 💻 Windows Survey (`win-survey.js`)
*   **Intelligent Stealth Hashing**: In-memory MD5 calculation targets only suspicious execution paths (e.g., `Users`, `ProgramData`, `Temp`) to aggressively optimize speed without creating process anomalies (no `certutil.exe` or `powershell.exe`).
*   **Process Verification**: Uses native COM file metadata to identify and flag running processes published by Microsoft natively in the results format.
*   **WMI Obfuscation**: String fragmentation for namespaces and classes to evade static signature analysis.
*   **Persistence Analysis**: Queries Scheduled Tasks (API 2.0), Startup Keys, and "fileless" WMI Event Subscriptions.
*   **Infrastructure Sensitivity**: Identifies active Kernel Drivers and captures the Neighbor (ARP) cache.
*   **Remote Access**: Registry analysis for RDP status and WinRM listeners.
*   **Base64 Output**: Optional toggle to encode the results file on disk.

### 🐧 Linux Survey (`linux-survey.py`)
*   **Container Detection**: Automatically identifies if the script is running inside a Docker or Kubernetes container.
*   **Infrastructure Awareness**: Lists loaded Kernel Modules and identifies active init systems (Systemd/SysV).
*   **Secrets Discovery**: Full dump of all shell-level environment variables.
*   **SSH Analysis**: Scans for privileged SSH configurations and active `authorized_keys`.
*   **Network Mapping**: Native parsing of the Linux ARP cache.
*   **Logging**: Pulls the last 300 entries from the system audit logs.

## Usage

### Windows
Requires an **Administrative Command Prompt** for full access to Security logs and WMI namespaces.
```cmd
cscript /nologo win-survey.js
```

### Linux
Requires **root** privileges to read all process information and system configurations.
```bash
sudo python3 linux-survey.py
```

## Disclaimer
These scripts are intended for authorized security assessments and administrative troubleshooting only. Unauthorized use on systems you do not own or have explicit permission to access is prohibited.
