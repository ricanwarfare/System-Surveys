# System Surveys — Cross-Platform System Reconnaissance

Lightweight, living-off-the-land system survey scripts for Linux and Windows. Minimal footprint, no dependencies, reads from native OS APIs.

## Features

All scripts share these capabilities:

- **Process hashing** — optional MD5 (Windows) or SHA-256 (Linux) for running process binaries; **off by default** for speed, enable with `--hash`
- **Environment variable sanitization** — secrets are masked before output
- **CLI argument support** — flexible runtime configuration
- **Text + JSON output** (Linux) / **Base64 encoded output** (Windows)
- **Container/virtualization detection**
- **SSH analysis**
- **Firewall and security product detection**
- **Scheduled task enumeration**
- **Network connections** — TCP/UDP, IPv4/IPv6
- **Shell history sampling**

---

## Linux Script — `linux-survey.py`

Pure `/proc` filesystem reads. No subprocess calls — fully LotL.

### Modules

| Module | What It Collects |
|---|---|
| `system_info` | Hostname, OS, kernel, uptime, CPU, memory |
| `processes` | Running processes (optional SHA-256 hashes) |
| `network` | TCP4, TCP6, UDP4, UDP6 connections |
| `arp` | ARP cache from `/proc/net/arp` |
| `users` | Local users and groups |
| `services` | Init system services (systemd/SysV) |
| `packages` | Installed packages (DEB/RPM/pacman/apk/portage) + distro info |
| `firewall` | iptables, nftables, UFW, firewalld rules |
| `scheduled_tasks` | Cron jobs and systemd timers |
| `security_products` | SELinux, AppArmor, antivirus, EDR agents |
| `persistence` | Startup scripts, rc.local, systemd unit overrides |
| `shell_history` | Shell history sampling (bash, zsh) |
| `env_vars` | Environment variables (sanitized) |
| `container` | Container/virtualization detection |
| `kernel_modules` | Loaded kernel modules |
| `ssh_analysis` | SSH config, authorized_keys, host keys |
| `logs` | Recent system log entries |

### CLI Options

```
python3 linux-survey.py [options]

  -o, --output PATH     Output file path (default: survey_<hostname>.txt)
  -f, --format FORMAT   Output format: text or json (default: text)
      --skip MODULES    Module names to skip
      --only MODULES   Only run these modules
      --no-hash         Skip process hashing (default: hashing off)
      --hash            Enable SHA-256 process hashing
      --log-depth N     Number of log entries (default: 300)
  -h, --help            Show help message
```

### Examples

```bash
# Full survey (no hashing, fastest)
python3 linux-survey.py

# With SHA-256 process hashing
python3 linux-survey.py --hash

# JSON output to file, skip kernel_modules
python3 linux-survey.py --format json --output survey.json --skip kernel_modules

# Only network and processes
python3 linux-survey.py --only network,processes

# Custom output path
python3 linux-survey.py --output /tmp/survey_$(hostname).txt
```

---

## Windows Script — `win-survey.js`

Pure WMI + Registry reads. No .NET, no PowerShell dependency. Runs via `cscript`.

### Modules

| Module | What It Collects |
|---|---|
| `system_info` | Hostname, OS, architecture, uptime, install date |
| `network` | ipconfig /all, netstat -anob, network shares |
| `users` | Local users, admin group members, logon sessions |
| `processes` | Running processes (optional MD5 hashes, company info) |
| `services` | Windows services, states, and start modes |
| `startup` | Autorun entries (Registry, Startup folder) |
| `scheduled_tasks` | Scheduled tasks (API 2.0) |
| `WMI_persistence` | WMI event subscriptions (fileless persistence) |
| `PS_history` | PowerShell history sampling |
| `security_products` | Antivirus, EDR, firewall products |
| `hotfixes` | Installed patches and updates |
| `installed_programs` | Registered applications with versions |
| `env_vars` | Environment variables (sanitized) |
| `remote_access` | RDP status, WinRM listeners |
| `drivers` | Loaded kernel drivers with company info |
| `neighbors` | ARP cache (MSFT_NetNeighbor) |
| `firewall` | All enabled firewall rules (direction, action, protocol, ports) |
| `event_logs` | System, Security, and PowerShell event logs with category |

### CLI Options

```
cscript /nologo win-survey.js [options]

  --output PATH         Output file path (default: survey_<COMPUTERNAME>.txt)
  --encode              Base64-encode the output
  --no-hash             Skip process hashing (default: hashing off)
  --hash                Enable MD5 process hashing via certutil
  --help                Show help message
```

> **Note on WSH deprecation:** Microsoft has announced future deprecation of Windows Script Host. These scripts currently work on Windows 7+ but may require migration to a newer runtime in future Windows releases.

---

## Feature Parity Matrix

| Capability | Linux | Windows |
|---|:---:|:---:|
| System info | ✅ | ✅ |
| Process enumeration | ✅ | ✅ |
| Process hashing | ✅ SHA-256 | ✅ MD5 |
| Network connections | ✅ /proc | ✅ ipconfig + netstat |
| ARP/neighbor cache | ✅ | ✅ |
| Users & groups | ✅ | ✅ |
| Services | ✅ | ✅ |
| Scheduled tasks | ✅ | ✅ |
| Firewall rules | ✅ | ✅ |
| Security products | ✅ | ✅ |
| Persistence mechanisms | ✅ | ✅ |
| Shell/PS history | ✅ | ✅ |
| Environment variables | ✅ | ✅ |
| SSH analysis | ✅ | — |
| Container detection | ✅ | — |
| Kernel modules/drivers | ✅ | ✅ |
| Installed packages | ✅ | ✅ |
| Hotfixes/patches | — | ✅ |
| Remote access config | — | ✅ |
| WMI persistence | — | ✅ |
| Event logs | ✅ | ✅ |
| JSON output | ✅ | — |
| Base64 output | — | ✅ |
| Hostname in filename | ✅ | ✅ |

---

## Security Notes

- **Environment variables are sanitized** — values matching common secret patterns (API keys, tokens, passwords) are masked in output.
- **Process hashing is OFF by default** — enable with `--hash` when you need file integrity verification. Linux uses SHA-256, Windows uses MD5 (certutil).
- **Batch file injection mitigated** — Windows script escapes special characters in process paths.
- **No data leaves the system** — all output is written locally. No network calls, no telemetry, no phone-home.
- **Authorized use only** — these tools are intended for security assessments and administrative troubleshooting on systems you own or have explicit permission to assess.

---

## Contributing

Pull requests are welcome. By submitting a PR you confirm that your contribution is for authorized security assessment use only.

---

## License

[MIT](LICENSE)