# CODY_REVIEW.md — System-Surveys Code Review

**Reviewer**: Cody (Senior Python Architect)  
**Date**: 2026-04-19  
**Files Reviewed**: `linux-survey.py`, `win-survey.js`, `README.md`

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Code Quality](#code-quality)
   - [Architecture & Structure](#architecture--structure)
   - [Error Handling & Edge Cases](#error-handling--edge-cases)
   - [Security Concerns](#security-concerns)
   - [Cross-Platform Compatibility](#cross-platform-compatibility)
   - [Code Duplication](#code-duplication)
3. [Improvements (Concrete)](#improvements-concrete)
   - [Bug Fixes & Logic Errors](#bug-fixes--logic-errors)
   - [Performance Optimizations](#performance-optimizations)
   - [Better Error Messages / UX](#better-error-messages--ux)
   - [Missing Validations](#missing-validations)
   - [Dependency Management](#dependency-management)
4. [New Features (Prioritized)](#new-features-prioritized)
   - [Feature Parity Between Scripts](#feature-parity-between-scripts)
   - [Output Format Improvements](#output-format-improvements)
   - [Remote Execution / Centralized Collection](#remote-execution--centralized-collection)
   - [Diff / Comparison Between Runs](#diff--comparison-between-runs)
   - [Integration with Common Tools](#integration-with-common-tools)
5. [Appendix: Feature Parity Matrix](#appendix-feature-parity-matrix)

---

## Executive Summary

Both scripts achieve their stated goal — lightweight, "living off the land" system survey with minimal footprint. The **Windows script** (`win-survey.js`) is significantly more feature-rich than the **Linux script** (`linux-survey.py`), covering persistence mechanisms, security products, firewall rules, installed programs, and event logs. The Linux script is a solid `/proc`-based foundation but lacks depth in several areas (no firewall check, no installed package enumeration, no scheduled task equivalent, no driver/module signing verification).

The most critical issues are: **security concerns with the Windows batch hashing approach**, **bare `except:` clauses in the Linux script that silently swallow errors**, **inconsistent error handling patterns**, and **the Linux script's reliance on `subprocess` for `ps` and `netstat` which undermines the LotL philosophy**.

Overall verdict: **Good v0.1 foundation. Needs hardening, feature parity, and structured output before production use.**

---

## Code Quality

### Architecture & Structure

**Linux (`linux-survey.py`)** — 🟡 High

- **Flat procedural design**: All survey functions are top-level, called sequentially from `main()`. No classes, no module encapsulation. For a single-file tool this is acceptable, but it limits testability and extensibility.
- **Global mutable state**: `OUTPUT_BUFFER` is a module-level list mutated by every `report()` call. This is a side-effect-driven pattern that makes unit testing difficult — you can't run a single survey function in isolation without polluting global state.
- **No config object**: Constants like `RESULTS_FILE` and `LOG_DEPTH` are module-level globals. A `Config` dataclass would make the script testable and allow CLI overrides.
- **No CLI argument parsing**: The script has zero command-line options. You can't skip modules, change the output path, or adjust verbosity.

**Windows (`win-survey.js`)** — 🟡 High

- **Similarly flat**: All functions are global, no encapsulation. Expected for JScript/WSH, but the lack of modularity makes it harder to selectively enable/disable survey modules.
- **Global WMI connection**: The `wmi` object is created once at module scope. This is efficient but means a single WMI failure kills the entire script.
- **String obfuscation pattern**: The `_w` variable fragments WMI namespace strings (`"win" + "mgmts" + ...`). This is intentional for AV evasion, but it hurts readability and makes the code look suspicious to reviewers. The README should document this design decision more prominently.
- **No CLI argument parsing**: Same as Linux — no way to control behavior from the command line.

**Recommendation**: Both scripts would benefit from a simple module registry pattern:

```python
# Linux example
SURVEY_MODULES = [
    ("system_info", survey_system_info),
    ("processes", survey_processes),
    ("network", survey_network),
    # ...
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip", nargs="*", help="Modules to skip")
    parser.add_argument("--only", nargs="*", help="Only run these modules")
    args = parser.parse_args()
    
    modules = filter_modules(SURVEY_MODULES, args.skip, args.only)
    for name, func in modules:
        func()
```

### Error Handling & Edge Cases

**Linux** — 🔴 Critical

1. **Bare `except:` clauses everywhere**: Almost every survey function uses `except:` with no exception type. This catches `KeyboardInterrupt`, `SystemExit`, and `MemoryError` — all of which should propagate. It also makes debugging impossible because errors are silently swallowed.

   ```python
   # Current (BAD):
   try:
       with open("/proc/meminfo", "r") as f:
           ...
   except:
       pass
   
   # Should be:
   try:
       with open("/proc/meminfo", "r") as f:
           ...
   except (PermissionError, FileNotFoundError) as e:
       report(f"[!] Could not read /proc/meminfo: {e}")
   ```

2. **No error reporting for failed modules**: When a survey function fails, it silently produces no output. The user has no idea that, e.g., `survey_network()` failed vs. found nothing.

3. **`survey_processes()` — broken for zombie/deleted processes**: `os.readlink(f"/proc/{pid}/exe")` throws `FileNotFoundError` for zombie processes and processes whose binary was deleted (`(deleted)` suffix). The `except: continue` hides this entirely.

4. **`survey_network()` — `parse_addr` defined inside loop**: The `parse_addr` function is redefined on every iteration of the for-loop. While not a bug per se, it's inefficient and unusual. It should be a module-level function.

5. **No handling of `/proc` being unmounted or restricted**: On hardened systems, `/proc` may be mounted with `hidepid=2` which restricts non-root users from seeing other users' processes. The script should detect and report this.

**Windows** — 🟡 High

1. **WMI error handling is inconsistent**: `QueryWMI()` has a try/catch that logs errors, but direct WMI calls (like `SurveyWMIPersistence`) have their own try/catch with different formatting. The `SurveyProcesses` function does WMI via `QueryWMI` but then does batch hashing with a completely different error pattern.

2. **`SurveyEventLogs()` — Security log requires SeSecurityPrivilege**: The script queries the Security event log but doesn't attempt to enable the privilege first. This will silently fail on most systems. The `QueryWMI` error handler will catch it, but the message will be generic.

3. **Batch hashing temp file cleanup**: If the script crashes between creating the `.bat` and `.txt` temp files and the `DeleteFile` calls, orphan files are left in `%TEMP%`. Should use a try/finally pattern (as close as JScript allows).

4. **`SurveyStartup()` — WbemLocator re-created each iteration**: The `locator` and `reg` objects are created inside the for-loop for each registry key. They should be created once outside the loop.

### Security Concerns

#### 🔴 Critical: Windows Batch Hashing — Command Injection

The `SurveyProcesses()` function writes executable paths directly into a batch file without sanitization:

```javascript
for (var p in uniquePaths) {
    if (fso.FileExists(p)) {
        batFile.WriteLine('certutil -hashfile "' + p + '" MD5');
    }
}
```

If a process path contains special characters like `&`, `|`, `<`, `>`, or `^`, the batch file will break or execute arbitrary commands. While this is unlikely for legitimate process paths, a maliciously-named binary (e.g., `C:\Users\test&calc.exe\payload.exe`) would cause command injection.

**Fix**: Sanitize the path or use a different approach:

```javascript
// Option 1: Escape special characters for batch
function EscapeBatch(str) {
    return str.replace(/([&|^<>"])/g, "^$1");
}
batFile.WriteLine('certutil -hashfile "' + EscapeBatch(p) + '" MD5');

// Option 2 (better): Use WScript.Shell.Exec with individual certutil calls
// and parse stdout in real-time, avoiding batch files entirely
```

#### 🔴 Critical: Environment Variable Dumping — Info Disclosure

Both scripts dump ALL environment variables. This is a significant info disclosure risk:

- **Linux**: `survey_env_vars()` dumps everything, including `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `API_KEY` variants, `SSH_PRIVATE_KEY`, etc.
- **Windows**: `SurveyEnvVars()` dumps all `PROCESS` environment variables.

**Fix**: Add a filtering/sanitization layer:

```python
SENSITIVE_PATTERNS = re.compile(
    r'(key|secret|password|token|credential|private)', re.IGNORECASE
)

def safe_env_value(key, value):
    if SENSITIVE_PATTERNS.search(key):
        return f"{value[:4]}{'*' * 8}" if len(value) > 4 else "****"
    return value

for k, v in os.environ.items():
    report(f"  {k}={safe_env_value(k, v)}")
```

#### 🟡 High: Linux MD5 Hashing — Deprecated Algorithm

`hashlib.md5()` is used for process hashing. MD5 is cryptographically broken. While the use case here is integrity checking (not security), SHA-256 would be more defensible for forensic purposes (matching against known-good hash databases like NIST NSRL).

#### 🟡 High: README Documents Stealth Capabilities

The README explicitly documents "stealth" features, WMI obfuscation, and bypass techniques. While this is useful for the intended audience (authorized security assessors), it makes the repo a higher-value target for misuse. Consider:
- Adding a `CONTRIBUTING.md` with a responsible disclosure / authorized-use-only clause
- Adding a `LICENSE` file (currently missing) with appropriate terms

#### 🟢 Nice-to-have: Linux Script Uses `subprocess`

The Linux script calls `ps -efH` and `netstat -antup` via `subprocess`, which creates new processes that are visible to `auditd` and process monitoring tools. This contradicts the "Living off the Land" philosophy stated in the README. The `/proc`-based process listing is already implemented — the `ps` call is redundant and noisy.

### Cross-Platform Compatibility

**Linux** — 🟡 High

1. **Hardcoded `/var/log/syslog` and `/var/log/messages`**: Modern systems use `journald`. The script should check `journalctl` availability and fall back gracefully.
2. **Only checks DEB and RPM package managers**: Misses Arch (pacman), Alpine (apk), Gentoo (portage), NixOS, etc.
3. **`/proc/net/tcp` parsing assumes IPv4**: No support for `/proc/net/tcp6` (IPv6 connections).
4. **No LSB/os-release parsing**: The "System Information" section only shows kernel version, not distro name/version.

**Windows** — 🟢 Nice-to-have

1. **JScript/WSH is deprecated**: Microsoft has been deprecating WSH components. Windows 11 24H2+ may have WSH disabled by default. The README should note this.
2. **`SecurityCenter2` WMI namespace is client-only**: The script already handles the error, but it should explicitly log "Server OS detected — SecurityCenter2 unavailable" rather than the generic error message.
3. **`MSFT_NetNeighbor` requires Win8+**: The fallback message is adequate but could suggest running `arp -a` as a fallback.

### Code Duplication

Between the two scripts, there is structural duplication in:

| Concern | Linux | Windows | Duplication Level |
|---------|-------|---------|-------------------|
| Output buffering & file write | `OUTPUT_BUFFER` + `report()` | `logBuffer` + `Log()` | 🟡 High — identical pattern |
| Section formatting | `section()` | `Section()` | 🟡 High — same borders |
| Padding function | `pad()` | `Pad()` | 🟡 High — same logic |
| Process hashing | `get_file_md5()` per-process | batch `certutil` | 🟢 Low — different approach (good) |
| Environment dump | `survey_env_vars()` | `SurveyEnvVars()` | 🟡 High — same concern |
| Network neighbor scan | `survey_arp()` | `SurveyNeighbors()` | 🟢 Low — different sources |

The output formatting duplication is unavoidable since they're different languages, but a **shared output schema** would help. See [Output Format Improvements](#output-format-improvements).

---

## Improvements (Concrete)

### Bug Fixes & Logic Errors

#### 🔴 Critical: `survey_network()` — `parse_addr` redefined every iteration

```python
# Current (line ~87):
for line in lines:
    parts = line.split()
    local = parts[1]
    remote = parts[2]
    state = parts[3]
    
    def parse_addr(addr):  # ← Redefined N times!
        ...
```

**Fix**: Move to module level:

```python
def parse_proc_addr(addr):
    """Convert hex IP:port from /proc/net/tcp to dotted-quad:port."""
    try:
        ip_hex, port_hex = addr.split(':')
        ip = ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(len(ip_hex)-2, -1, -2)])
        port = str(int(port_hex, 16))
        return f"{ip}:{port}"
    except (ValueError, IndexError):
        return addr
```

#### 🔴 Critical: `survey_network()` — State codes are numeric, not human-readable

The TCP state in `/proc/net/tcp` is a hex code (e.g., `0A` = LISTEN, `06` = TIME_WAIT). The script just prints the raw hex. Nobody knows what `0A` means.

**Fix**:

```python
TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING',
}

state_name = TCP_STATES.get(state, f"UNKNOWN({state})")
```

#### 🔴 Critical: `survey_processes()` — Hashing `/proc/{pid}/exe` reads the symlink target, not the binary

`os.readlink(f"/proc/{pid}/exe")` resolves the symlink but `get_file_md5(f"/proc/{pid}/exe")` opens the proc entry and reads the actual binary content through it. This works on Linux (reading through `/proc/{pid}/exe` gives you the binary), but it **fails for deleted binaries** where the symlink target ends with `(deleted)`. The MD5 will still work through the proc fd, but `readlink` will show `(deleted)` — the name and the hash are both reported but the "(deleted)" status isn't flagged.

**Fix**: Detect and flag deleted binaries:

```python
exe_path = os.readlink(f"/proc/{pid}/exe")
deleted = exe_path.endswith("(deleted)")
md5 = get_file_md5(f"/proc/{pid}/exe")
if deleted:
    report(pad(pid, 8) + pad(name[:24], 25) + pad(md5, 34) + "[DELETED] " + exe_path)
```

#### 🟡 High: Windows `SurveyUsers()` — Admin group member parsing is fragile

```javascript
var memberPath = assoc.PartComponent; 
Log("  Admin Member: " + memberPath.split('Name="')[1].split('"')[0]);
```

If `PartComponent` doesn't contain `Name="`, this throws a runtime error. The split could fail on non-standard WMI object paths.

**Fix**:

```javascript
var memberPath = assoc.PartComponent;
var nameMatch = memberPath.match(/Name="([^"]+)"/);
if (nameMatch) {
    Log("  Admin Member: " + nameMatch[1]);
} else {
    Log("  Admin Member: " + memberPath); // Fallback: log raw path
}
```

#### 🟡 High: Linux `survey_logs()` — Reading `/var/log/syslog` as regular user will fail silently

The script tries to open `/var/log/syslog` which is typically `root:adm` with `640` permissions. As non-root, this fails and the bare `except` swallows it. The non-root warning at the top says "some information will be missing" but doesn't say what.

**Fix**: Check readability first:

```python
def survey_logs():
    section(f"Recent Logs (Last {LOG_DEPTH} lines)")
    log_file = "/var/log/syslog" if os.path.exists("/var/log/syslog") else "/var/log/messages"
    if not os.path.exists(log_file):
        report("[!] No system log file found")
        return
    if not os.access(log_file, os.R_OK):
        report(f"[!] Cannot read {log_file} (try running as root)")
        return
    # ... proceed with reading
```

#### 🟡 High: Windows `SurveyProcesses()` — `Math.random()` for temp file names is weak

```javascript
var batPath = tempDir + "\\sys_hash_" + Math.floor(Math.random() * 10000) + ".bat";
```

`Math.random() * 10000` gives only ~13 bits of entropy. Collisions are possible, especially in concurrent runs. More importantly, the prefix `sys_hash_` is suspicious and identifiable.

**Fix**:

```javascript
// Use timestamp + random for better uniqueness
var ts = new Date().getTime();
var rnd = Math.floor(Math.random() * 100000);
var batPath = tempDir + "\\" + ts + rnd + ".tmp";
var outPath = tempDir + "\\" + ts + rnd + "o.tmp";
```

### Performance Optimizations

#### 🟡 High: Linux — Read `/proc/cpuinfo` more efficiently

The current code iterates every line in `/proc/cpuinfo` just to count processors:

```python
with open("/proc/cpuinfo", "r") as f:
    count = 0
    for line in f:
        if "processor" in line: count += 1
```

**Fix**: Use `os.cpu_count()` (available since Python 3.4):

```python
report("CPUs: " + str(os.cpu_count() or "N/A"))
```

#### 🟡 High: Linux — `survey_process_tree()` spawns `ps` subprocess

This contradicts the LotL philosophy and is slower than reading `/proc` directly. Build the tree from `/proc` data:

```python
def survey_process_tree():
    section("Process Hierarchy")
    pids = [d for d in os.listdir('/proc') if d.isdigit()]
    tree = {}  # ppid -> [pid, ...]
    for pid in sorted(pids, key=int):
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                fields = f.read().split()
                ppid = fields[3]  # 4th field is ppid
                name = fields[1].strip('()')
                tree.setdefault(ppid, []).append((pid, name))
        except (FileNotFoundError, PermissionError):
            continue
    
    def print_tree(ppid, depth=0):
        for pid, name in tree.get(ppid, []):
            report("  " * depth + f"({pid}) {name}")
            print_tree(pid, depth + 1)
    
    print_tree("1")  # Start from init
```

#### 🟡 High: Windows — Batch hashing is faster than per-file but still serial

The current approach writes a `.bat` file and runs it synchronously via `shell.Run(..., 0, true)`. For systems with hundreds of processes, this is still slow because `certutil` is invoked once per file.

**Fix**: Consider using PowerShell's `Get-FileHash` with parallel runs (if available), or accept the trade-off and document it. Alternatively, implement a COM-based MD5 in pure JScript (the original code had this before it was removed — the comment says "MD5 engine removed").

#### 🟢 Nice-to-have: Linux — Sort TCP connections by state

Grouping connections by state (LISTEN first, then ESTABLISHED, etc.) makes the output much more scannable:

```python
from collections import defaultdict
connections_by_state = defaultdict(list)
# ... collect connections ...
for state in ['0A', '01', '06', ...]:  # LISTEN, ESTABLISHED, TIME_WAIT
    for conn in connections_by_state.get(state, []):
        report(conn)
```

### Better Error Messages / UX

#### 🟡 High: Both scripts need module-level success/failure indicators

Currently, if a module produces no output, you can't tell if it succeeded-but-found-nothing or failed-silently. Add explicit status lines:

```python
def survey_kernel_modules():
    section("Loaded Kernel Modules (Sample)")
    try:
        with open("/proc/modules", "r") as f:
            modules = f.readlines()
            if not modules:
                report("  (No kernel modules found — unusual!)")
            for i, line in enumerate(modules[:20]):
                report("  " + line.split()[0])
            if len(modules) > 20:
                report(f"  ... {len(modules) - 20} more modules loaded")
    except PermissionError as e:
        report(f"[!] Cannot read /proc/modules: {e}")
    except FileNotFoundError:
        report("[!] /proc/modules not found (non-standard kernel?)")
```

#### 🟡 High: Linux — Non-root warning should list affected modules

```python
if os.geteuid() != 0:
    print("WARNING: Script not running as root. The following modules will have limited data:")
    print("  - Processes: Cannot read /proc/{pid}/exe for other users' processes")
    print("  - Network: /proc/net/tcp may show limited connection info")
    print("  - Logs: Cannot read /var/log/syslog")
    print("  - ARP: Full cache may not be visible")
```

#### 🟢 Nice-to-have: Progress indicator for long-running modules

The Windows event log scan can take a long time. Add a simple counter:

```javascript
// Inside SurveyEventLogs enumeration:
if (count % 25 === 0) WScript.Echo("  ... scanned " + count + " events");
```

### Missing Validations

#### 🔴 Critical: Linux — No validation of `/proc/net/tcp` line format

```python
parts = line.split()
local = parts[1]  # IndexError if line has fewer fields
remote = parts[2]
state = parts[3]
```

If any line is malformed, this crashes the entire network section (or is silently caught by the bare `except`). Add bounds checking:

```python
parts = line.split()
if len(parts) < 4:
    continue
local, remote, state = parts[1], parts[2], parts[3]
```

#### 🟡 High: Windows — No validation of WMI query string injection

In `SurveyUsers()`, the admin group query constructs a WMI query with `group.Domain` and `group.Name` interpolated directly:

```javascript
var query = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='" + group.Domain + "',Name='" + group.Name + "'\"";
```

If domain or name contains a single quote, the WMI query breaks. Unlikely but possible in AD environments with unusual naming.

#### 🟡 High: Linux — No check for `/proc` availability

The entire script assumes `/proc` is mounted. On FreeBSD, macOS, or WSL1, `/proc` may not exist. Add an early check:

```python
if not os.path.ismount('/proc'):
    print("ERROR: /proc is not mounted. This script requires a Linux system with procfs.")
    sys.exit(1)
```

### Dependency Management

#### Linux — 🟢 Nice-to-have

The Linux script has zero external dependencies, which is excellent for the use case. All imports are stdlib. However:
- `pwd` and `grp` are Unix-only — this should be documented
- No `requirements.txt` needed, but a `python3 -c "import pwd, grp"` pre-flight check would be nice

#### Windows — 🟢 Nice-to-have

The Windows script requires zero dependencies beyond WSH. However:
- Some features require specific Windows versions (Schedule.Service API 2.0 = Win7+, SecurityCenter2 = Vista+, MSFT_NetNeighbor = Win8+). A version-check preamble would help:

```javascript
// At the top of main:
var osVersion = shell.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentVersion");
Log("Detected Windows version: " + osVersion);
```

---

## New Features (Prioritized)

### Feature Parity Between Scripts

#### 🟡 High: Features Linux is missing (that Windows has)

| Feature | Windows Has It? | Linux Equivalent |
|---------|:-:|:-|
| **Firewall status & rules** | ✅ `HNetCfg.FwPolicy2` | `iptables -L` or parse `/sys/class/net/*/` + nftables |
| **Installed packages enumeration** | ✅ Registry-based | `dpkg -l` / `rpm -qa` / `pacman -Q` |
| **Scheduled tasks/cron detail** | ✅ Schedule.Service | Parse `/etc/cron.d/*`, `/var/spool/cron/*`, systemd timers |
| **Startup/persistence detail** | ✅ Registry + WMI | Parse `/etc/init.d/*`, systemd unit `WantedBy=`, `/etc/rc.local`, `.bashrc`, `.profile` |
| **Security product detection** | ✅ SecurityCenter2 | Check for `clamd`, `ossec`, `auditd`, `selinux` status |
| **Driver/module signing** | ✅ `Win32_PnPSignedDriver` | Check `/sys/module/*/initstate`, `modinfo` signing info |
| **Hotfix/patch level** | ✅ `Win32_QuickFixEngineering` | `uname -rv` + `apt list --upgradable` / `yum check-update` |
| **Remote access config** | ✅ Registry RDP/WinRM | Check `/etc/ssh/sshd_config` (already partially done) |
| **PowerShell/bash history** | ✅ PS history paths | Check `~/.bash_history`, `~/.zsh_history`, `~/.python_history` |

**Concrete implementation — Linux firewall check**:

```python
def survey_firewall():
    section("Firewall Status")
    # Check iptables
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            report("iptables rules found:")
            for line in result.stdout.splitlines()[:30]:
                report("  " + line)
        else:
            report("[!] iptables returned non-zero (may need root)")
    except FileNotFoundError:
        report("[!] iptables not found")
    
    # Check nftables
    if os.path.exists("/etc/nftables.conf"):
        report("nftables config found: /etc/nftables.conf")
    
    # Check UFW
    if os.path.exists("/etc/ufw/ufw.conf"):
        try:
            with open("/etc/ufw/ufw.conf") as f:
                for line in f:
                    if "ENABLED" in line.upper():
                        report("UFW Status: " + line.strip())
        except PermissionError:
            report("[!] Cannot read UFW config (need root)")
```

**Concrete implementation — Linux scheduled tasks**:

```python
def survey_scheduled_tasks():
    section("Scheduled Tasks (Cron & Systemd Timers)")
    
    # Systemd timers
    if os.path.exists("/run/systemd/system"):
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                report("Systemd Timers:")
                for line in result.stdout.splitlines()[:20]:
                    report("  " + line)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    # Cron directories
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", 
                 "/etc/cron.weekly", "/etc/cron.monthly"]
    for d in cron_dirs:
        if os.path.isdir(d):
            try:
                entries = os.listdir(d)
                if entries:
                    report(f"\n{d}:")
                    for entry in entries:
                        report(f"  {entry}")
            except PermissionError:
                report(f"[!] Cannot read {d}")
    
    # User crontabs
    if os.path.isdir("/var/spool/cron/crontabs"):
        try:
            for user_file in os.listdir("/var/spool/cron/crontabs"):
                report(f"  User crontab: {user_file}")
        except PermissionError:
            report("[!] Cannot read /var/spool/cron/crontabs (need root)")
```

#### 🟡 High: Features Windows is missing (that Linux has)

| Feature | Linux Has It? | Windows Equivalent |
|---------|:-:|---|
| **Container detection** | ✅ `/.dockerenv` + cgroup | Check `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` for Docker, or `env PROGRAMDATA=Docker` |
| **SSH analysis** | ✅ sshd_config + authorized_keys | Check `C:\ProgramData\ssh\sshd_config` (OpenSSH on Windows) |
| **Kernel module list** | ✅ `/proc/modules` | `Win32_PnPSignedDriver` (already done) |

### Output Format Improvements

#### 🔴 Critical: Both scripts need structured output (JSON)

The current text-only output is fine for human reading but unusable for automated analysis, diffing, or ingestion. Adding JSON output is the single highest-impact improvement.

**Proposed schema (shared between both scripts)**:

```json
{
  "metadata": {
    "hostname": "web01",
    "os": "Linux 6.1.0",
    "timestamp": "2026-04-19T15:10:00-05:00",
    "script_version": "1.0.0",
    "run_as_root": true
  },
  "system": {
    "hostname": "web01",
    "kernel": "6.1.0-17-amd64",
    "distro": "Debian 12.4",
    "cpu_count": 8,
    "memory_mb": 16384
  },
  "processes": [
    {
      "pid": 1234,
      "name": "nginx",
      "md5": "a1b2c3...",
      "cmdline": "/usr/sbin/nginx -g daemon on",
      "exe_path": "/usr/sbin/nginx",
      "exe_deleted": false
    }
  ],
  "network": {
    "interfaces": [...],
    "tcp_connections": [...],
    "arp_cache": [...]
  },
  "users": {
    "local_accounts": [...],
    "admin_group_members": [...]
  },
  "persistence": {
    "cron_jobs": [...],
    "startup_items": [...],
    "scheduled_tasks": [...],
    "wmi_subscriptions": [...]
  }
}
```

**Implementation — Linux**:

```python
import json
from dataclasses import dataclass, field, asdict

@dataclass
class SurveyResult:
    metadata: dict = field(default_factory=dict)
    system: dict = field(default_factory=dict)
    processes: list = field(default_factory=list)
    network: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    # ...

result = SurveyResult()

# Each survey function populates its section:
def survey_system_info(result):
    result.system["hostname"] = os.uname().nodename
    result.system["kernel"] = os.uname().release
    # ...

# At the end:
if args.format == "json":
    with open("survey_results.json", "w") as f:
        json.dump(asdict(result), f, indent=2)
elif args.format == "text":
    # Current behavior
    with open(RESULTS_FILE, "w") as f:
        f.writelines(OUTPUT_BUFFER)
```

#### 🟡 High: CSV export for specific modules

For importing into spreadsheets or SIEM tools:

```python
import csv

def export_processes_csv(processes, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["PID", "Name", "MD5", "Cmdline", "Deleted"])
        for p in processes:
            writer.writerow([p["pid"], p["name"], p["md5"], p["cmdline"], p.get("deleted", "")])
```

#### 🟢 Nice-to-have: HTML report with syntax highlighting

A simple HTML template that color-codes suspicious items (deleted binaries, privileged users, open RDP, etc.) would make reports much more scannable for analysts.

### Remote Execution / Centralized Collection

#### 🟡 High: Add a `--output-dir` flag for centralized collection

When running via SSH or Ansible across many hosts, each host should write to a unique file:

```python
parser.add_argument("--output-dir", default=".", help="Directory for output files")
parser.add_argument("--prefix", default="", help="Prefix for output filenames (e.g., hostname)")

# At end:
filename = f"{args.prefix or os.uname().nodename}_survey_{timestamp}.{ext}"
output_path = os.path.join(args.output_dir, filename)
```

#### 🟡 High: Add Ansible ad-hoc compatibility

The scripts should exit with proper codes and suppress interactive output when run via Ansible:

```python
parser.add_argument("--quiet", action="store_true", help="Suppress stdout, only write to file")
parser.add_argument("--exit-code-on-error", action="store_true", 
                    help="Exit non-zero if any module fails")

# Ansible usage:
# ansible all -m script -a "linux-survey.py --json --quiet --output-dir /tmp/surveys"
```

#### 🟢 Nice-to-have: HTTP POST results to a collector

For fully automated collection:

```python
parser.add_argument("--post-url", help="POST JSON results to this URL")
parser.add_argument("--post-token", help="Authorization bearer token")

# At end:
if args.post_url:
    headers = {"Authorization": f"Bearer {args.post_token}", "Content-Type": "application/json"}
    requests.post(args.post_url, json=asdict(result), headers=headers, timeout=30)
```

### Diff / Comparison Between Runs

#### 🟡 High: Baseline comparison mode

For change detection (new processes, new network connections, new persistence):

```python
parser.add_argument("--baseline", help="Path to previous survey JSON for comparison")
parser.add_argument("--diff-only", action="store_true", help="Only show differences from baseline")

def compare_surveys(current, baseline):
    diff = {
        "new_processes": [],
        "removed_processes": [],
        "new_connections": [],
        "new_users": [],
        "new_persistence": [],
    }
    
    current_pids = {p["md5"]: p for p in current["processes"]}
    baseline_pids = {p["md5"]: p for p in baseline["processes"]}
    
    for md5, proc in current_pids.items():
        if md5 not in baseline_pids:
            diff["new_processes"].append(proc)
    
    for md5, proc in baseline_pids.items():
        if md5 not in current_pids:
            diff["removed_processes"].append(proc)
    
    return diff
```

### Integration with Common Tools

#### 🟡 High: Syslog/CEF output format

For SIEM ingestion (Splunk, ELK, QRadar), a CEF (Common Event Format) output mode:

```python
def to_cef(result):
    """Convert survey results to CEF key-value pairs."""
    lines = []
    for proc in result["processes"]:
        cef = (f"CEF:0|SystemSurvey|1.0|100|PROCESS|Process Found|5|"
               f"src={result['system']['hostname']} "
               f"pid={proc['pid']} "
               f"fname={proc['name']} "
               f"fileHash={proc['md5']}")
        lines.append(cef)
    return "\n".join(lines)
```

#### 🟡 High: Splunk KV mode output

```python
def to_splunk_kv(result):
    """Convert to Splunk key=value format."""
    lines = []
    for proc in result["processes"]:
        kv = (f'host={result["system"]["hostname"]} '
              f'event_type=process '
              f'pid={proc["pid"]} '
              f'process_name="{proc["name"]}" '
              f'md5={proc["md5"]}')
        lines.append(kv)
    return "\n".join(lines)
```

#### 🟢 Nice-to-have: YARA integration

Scan running processes against YARA rules:

```python
parser.add_argument("--yara-rules", help="Path to YARA rule file for process scanning")
# Requires yara-python — optional dependency
```

---

## Appendix: Feature Parity Matrix

| Feature / Module | Linux | Windows | Parity? |
|---|:-:|:-:|:-:|
| System info (hostname, OS, CPU, RAM) | ✅ | ✅ | ✅ |
| Running processes with hash | ✅ | ✅ | ✅ |
| Process hierarchy/tree | ✅ (ps) | ❌ | ❌ |
| Network interfaces | ✅ | ✅ | ✅ |
| TCP connections | ✅ | ❌ | ❌ |
| UDP connections | ❌ | ❌ | — |
| ARP/neighbor cache | ✅ | ✅ | ✅ |
| Network shares | ❌ | ✅ | ❌ |
| Local users | ✅ | ✅ | ✅ |
| Admin/root group members | ✅ | ✅ | ✅ |
| Logon sessions | ❌ | ✅ | ❌ |
| Services/init system | ✅ (basic) | ✅ (full) | ❌ |
| Installed packages/programs | ❌ (detects pkg mgr only) | ✅ | ❌ |
| Scheduled tasks/cron | ✅ (paths only) | ✅ (full) | ❌ |
| Startup/persistence items | ✅ (basic cron) | ✅ (full) | ❌ |
| WMI persistence | N/A | ✅ | N/A |
| Firewall rules | ❌ | ✅ | ❌ |
| SSH/remote access config | ✅ | ✅ (RDP/WinRM) | ❌ |
| Security products | ❌ | ✅ | ❌ |
| Kernel drivers/modules | ✅ (names only) | ✅ (signed) | ❌ |
| Hotfixes/patches | ❌ | ✅ | ❌ |
| Environment variables | ✅ | ✅ | ✅ |
| Container detection | ✅ | ❌ | ❌ |
| Shell history check | ✅ (bash_history) | ✅ (PS history) | ✅ |
| Event/syslog reading | ✅ | ✅ | ✅ |
| Base64 output | ❌ | ✅ | ❌ |
| JSON output | ❌ | ❌ | — |
| CLI arguments | ❌ | ❌ | — |
| Progress indicator | ❌ | ❌ | — |
| Timestamps in output | ✅ (start only) | ✅ (start/end) | ❌ |
| Script version in output | ❌ | ❌ | — |
| Diff/baseline mode | ❌ | ❌ | — |
| Exit codes | ❌ | ❌ | — |

**Legend**: ✅ = Implemented, ❌ = Missing, N/A = Not applicable

---

*End of review. All code examples are suggestions — none have been applied to the source files.*