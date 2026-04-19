# System Surveys — Cross-Platform System Reconnaissance

Lightweight, living-off-the-land system survey scripts for Linux and Windows. Minimal footprint, no dependencies, reads from native OS APIs.

## Features

All scripts share these capabilities:

- **SHA-256 process hashing** — cryptographic integrity for running processes
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
| `processes` | Running processes with SHA-256 hashes |
| `network` | TCP4, TCP6, UDP4, UDP6 connections |
| `arp` | ARP cache from `/proc/net/arp` |
| `users` | Local users and groups |
| `services` | Init system services (systemd/SysV) |
| `packages` | Installed packages (DEB/RPM/pacman/apk/portage) |
| `firewall` | iptables, nftables, UFW, firewalld rules |
| `scheduled_tasks` | Cron jobs and systemd timers |
| `security_products` | SELinux, AppArmor, antivirus, EDR agents |
| `persistence` | Startup scripts, rc.local, systemd unit overrides |
| `shell_history` | Shell history sampling (bash, zsh, fish) |
| `env_vars` | Environment variables (sanitized) |
| `container` | Container/virtualization detection |
| `kernel_modules` | Loaded kernel modules |
| `ssh_analysis` | SSH config, authorized_keys, host keys |
| `logs` | Recent system log entries |

### CLI Options

```
python3 linux-survey.py [options]

  --output PATH         Write output to PATH (default: stdout)
  --format FORMAT       Output format: text or json (default: text)
  --skip MODULES        Comma-separated modules to skip
  --only MODULES        Run only these comma-separated modules
  --no-hash             Skip SHA-256 process hashing
  --log-depth N         Number of log entries to collect (default: 300)
  --help                Show help message
```

### Examples

```bash
# Full survey to stdout
python3 linux-survey.py

# JSON output to file, skip kernel_modules
python3 linux-survey.py --format json --output survey.json --skip kernel_modules

# Only network and processes
python3 linux-survey.py --only network,processes

# Skip hashing for faster results
python3 linux-survey.py --no-hash
```

---

## Windows Script — `win-survey.js`

Pure WMI + Registry reads. No .NET, no PowerShell dependency.

### Modules

| Module | What It Collects |
|---|---|
| `system_info` | Hostname, OS, architecture, uptime |
| `network` | Network adapters and TCP/UDP connections |
| `users` | Local and domain users |
| `processes` | Running processes with SHA-256 hashes |
| `services` | Windows services and states |
| `startup` | Autorun entries (Registry, Startup folder) |
| `scheduled_tasks` | Scheduled tasks (API 2.0) |
| `WMI_persistence` | WMI event subscriptions (fileless persistence) |
| `PS_history` | PowerShell history sampling |
| `security_products` | Antivirus, EDR, firewall products |
| `hotfixes` | Installed patches and updates |
| `installed_programs` | Registered applications |
| `env_vars` | Environment variables (sanitized) |
| `remote_access` | RDP status, WinRM listeners |
| `drivers` | Loaded kernel drivers |
| `neighbors` | ARP cache |
| `firewall` | Windows Firewall rules and profiles |
| `event_logs` | Recent Security and System event log entries |

### CLI Options

```
cscript /nologo win-survey.js [options]

  --output PATH         Write output to PATH (default: stdout)
  --encode              Base64-encode the output
  --no-hash             Skip SHA-256 process hashing
  --help                Show help message
```

> **Note on WSH deprecation:** Microsoft has announced future deprecation of Windows Script Host. These scripts currently work on Windows 7+ but may require migration to a newer runtime in future Windows releases.

---

## Feature Parity Matrix

| Capability | Linux | Windows |
|---|:---:|:---:|
| System info | ✅ | ✅ |
| Process enumeration | ✅ | ✅ |
| Process hashing (SHA-256) | ✅ | ✅ |
| Network connections | ✅ | ✅ |
| ARP/neighbor cache | ✅ | ✅ |
| Users | ✅ | ✅ |
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

---

## Security Notes

- **Environment variables are sanitized** — values matching common secret patterns (API keys, tokens, passwords) are masked in output.
- **Process hashing uses SHA-256** — not MD5, for stronger integrity verification.
- **Batch file injection mitigated** — Windows script validates input paths to prevent injection attacks.
- **No data leaves the system** — all output is written locally. No network calls, no telemetry, no phone-home.
- **Authorized use only** — these tools are intended for security assessments and administrative troubleshooting on systems you own or have explicit permission to assess.

---

## Contributing

Pull requests are welcome. By submitting a PR you confirm that your contribution is for authorized security assessment use only.

---

## License

[MIT](LICENSE)