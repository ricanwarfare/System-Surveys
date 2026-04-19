#!/usr/bin/env python3
import os
import sys
import hashlib
import pwd
import grp
import time
import re
import json
import argparse
from dataclasses import dataclass, field

# Sensitive environment variable pattern for masking
SENSITIVE_ENV_PATTERNS = re.compile(
    r'(key|secret|password|passwd|token|credential|private|auth)',
    re.IGNORECASE
)


def safe_env_value(key, value):
    if SENSITIVE_ENV_PATTERNS.search(key):
        return f"{value[:4]}{'*' * 8}" if len(value) > 4 else "****"
    return value


# Configuration
@dataclass
class Config:
    output_file: str = 'survey_results.txt'
    output_format: str = 'text'
    skip_modules: list = field(default_factory=list)
    only_modules: list = field(default_factory=list)
    no_hash: bool = False
    log_depth: int = 300

config = Config()
OUTPUT_BUFFER = []
json_sections = {}

def report(msg, section_name=None):
    """Log a message to text buffer and optionally to JSON section."""
    print(msg)
    OUTPUT_BUFFER.append(msg + "\n")

def json_report(section, data_dict):
    """Add structured data to JSON output."""
    json_sections[section] = data_dict

def pad(s, length):
    s = str(s)
    return s + " " * (length - len(s))

def section(title):
    border = "################################################################################"
    report("\n" + border)
    report("#  " + title.upper())
    report(border + "\n")

def get_file_hash(path):
    try:
        if not os.path.exists(path): return "N/A"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "ERROR"

# TCP state hex codes from /proc/net/tcp
TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING',
}


def parse_proc_addr(addr):
    """Convert a hex IP:port address from /proc/net/tcp to human-readable form.

    Addresses in /proc/net/tcp are in hex format like 0100007F:0050
    (little-endian IP followed by big-endian port).
    """
    ip_hex, port_hex = addr.split(':')
    ip = ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(len(ip_hex)-2, -1, -2)])
    port = str(int(port_hex, 16))
    return f"{ip}:{port}"


def parse_proc_addr_v6(addr):
    """Convert a hex IPv6:port address from /proc/net/tcp6 to human-readable form.

    IPv6 addresses in /proc/net/tcp6 are 32 hex chars (little-endian per 4-byte group)
    like 00000000000000000000000001000000:0050.
    Each 4-byte (8-char) group is byte-swapped internally.
    """
    ip_hex, port_hex = addr.split(':')
    port = str(int(port_hex, 16))

    # IPv6 is 32 hex chars; split into 8 groups of 4 hex chars
    # Each 4-char group (2 bytes) is stored little-endian, so swap within each group
    groups = []
    for i in range(0, len(ip_hex), 8):
        chunk = ip_hex[i:i+8]
        # Swap byte order within each 4-byte chunk: reverse pairs of 2 hex chars
        swapped = chunk[6:8] + chunk[4:6] + chunk[2:4] + chunk[0:2]
        groups.append(swapped)

    # Format as standard IPv6 colon-separated hextets
    hextets = []
    for g in groups:
        hextets.append(f"{int(g[0:4], 16):x}:{int(g[4:8], 16):x}")
    ip_str = ":".join(hextets)

    # Compress :: where possible (replace longest run of :0:0: with ::)
    # Simple approach: normalize consecutive :0: sequences
    parts = ip_str.split(':')
    # Find longest run of '0's
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for idx, p in enumerate(parts):
        if p == '0':
            if cur_start == -1:
                cur_start = idx
            cur_len += 1
            if cur_len > best_len:
                best_start = cur_start
                best_len = cur_len
        else:
            cur_start = -1
            cur_len = 0

    if best_len >= 2:
        compressed = ':'.join(parts[:best_start]) + '::' + ':'.join(parts[best_start + best_len:])
        # Remove leading/trailing stray colons from edge cases
        ip_str = compressed.strip(':')
        # Ensure double colon is present
        if '::' not in ip_str:
            ip_str = '::' + ip_str if best_start == 0 else ip_str + '::'
    else:
        ip_str = ':'.join(parts)

    return f"[{ip_str}]:{port}"


# --- Survey Modules ---

def survey_system_info():
    section("System Information")
    report("Host: " + os.uname().nodename)
    report("Kernel: " + os.uname().release)
    report("Version: " + os.uname().version)
    
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if "MemTotal" in line:
                    report("Memory: " + line.split(":")[1].strip())
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    cpu_count = os.cpu_count()
    if cpu_count is not None:
        report("CPUs: " + str(cpu_count))

def survey_processes():
    section("Running Processes (with SHA-256)")

    if os.geteuid() != 0:
        # Check if hidepid is set (can't see other users' processes)
        try:
            with open("/proc/1/comm", "r") as f:
                pass  # Can see PID 1 — hidepid not active
        except PermissionError:
            report("[!] /proc is restricted (hidepid=2). Only current user's processes visible.")

    report(pad("PID", 8) + pad("Name", 25) + pad("SHA-256", 66) + "Cmdline")
    report(pad("---", 8) + pad("----", 25) + pad("-------", 66) + "-------")
    
    pids = [d for d in os.listdir('/proc') if d.isdigit()]
    for pid in sorted(pids, key=int):
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()
            with open(f"/proc/{pid}/cmdline", "r") as f:
                # cmdline is null-terminated
                cmdline = f.read().replace('\0', ' ').strip()
            
            # exe is a symlink, readlink to get path or hash directly
            exe_path = os.readlink(f"/proc/{pid}/exe")
            deleted = exe_path.endswith("(deleted)")
            # To be stealthy, we hash the proc link directly
            file_hash = get_file_hash(f"/proc/{pid}/exe")

            deleted_flag = " [DELETED]" if deleted else ""
            if config.no_hash:
                report(pad(pid, 8) + pad(name[:24], 25) + cmdline[:100])
            else:
                report(pad(pid, 8) + pad(name[:24], 25) + pad(file_hash, 66) + cmdline[:100] + deleted_flag)
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            continue

def _parse_proc_net(proto_name, file_path, is_v6=False):
    """Helper to parse /proc/net/{tcp,udp,tcp6,udp6} files."""
    connections = []
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state_hex = parts[3]
                parser = parse_proc_addr_v6 if is_v6 else parse_proc_addr
                local_str = parser(local)
                remote_str = parser(remote)
                state_name = TCP_STATES.get(state_hex, state_hex)
                connections.append((local_str, remote_str, state_name, state_hex))
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return connections


def survey_network():
    section("Network Configuration")
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:] # Skip headers
            for line in lines:
                parts = line.split(":")
                if len(parts) > 1:
                    report("Interface: " + parts[0].strip())
    except (PermissionError, FileNotFoundError, OSError): pass

    # --- TCP IPv4 ---
    section("Active TCP Connections (IPv4)")
    report(pad("Local Address", 25) + pad("Remote Address", 25) + "State")
    for local, remote, state, _ in _parse_proc_net("TCP", "/proc/net/tcp", is_v6=False):
        report(pad(local, 25) + pad(remote, 25) + state)

    # --- TCP IPv6 ---
    section("Active TCP Connections (IPv6)")
    report(pad("Local Address", 48) + pad("Remote Address", 48) + "State")
    tcp6_conns = _parse_proc_net("TCP6", "/proc/net/tcp6", is_v6=True)
    if tcp6_conns:
        for local, remote, state, _ in tcp6_conns:
            report(pad(local, 48) + pad(remote, 48) + state)
    else:
        report("  (no IPv6 TCP connections found or file not readable)")

    # --- UDP IPv4 ---
    section("Active UDP Connections (IPv4)")
    report(pad("Local Address", 25) + pad("Remote Address", 25) + "State")
    udp_conns = _parse_proc_net("UDP", "/proc/net/udp", is_v6=False)
    if udp_conns:
        for local, remote, state, shex in udp_conns:
            # UDP states are simpler; show hex state if not in TCP_STATES
            state_display = state if state != shex else shex
            report(pad(local, 25) + pad(remote, 25) + state_display)
    else:
        report("  (no IPv4 UDP connections found or file not readable)")

    # --- UDP IPv6 ---
    section("Active UDP Connections (IPv6)")
    report(pad("Local Address", 48) + pad("Remote Address", 48) + "State")
    udp6_conns = _parse_proc_net("UDP6", "/proc/net/udp6", is_v6=True)
    if udp6_conns:
        for local, remote, state, shex in udp6_conns:
            state_display = state if state != shex else shex
            report(pad(local, 48) + pad(remote, 48) + state_display)
    else:
        report("  (no IPv6 UDP connections found or file not readable)")

def survey_users():
    section("Users & Groups")
    report("Local Accounts (Enabled Shells):")
    for user in pwd.getpwall():
        if user.pw_shell not in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]:
            report(f"  {user.pw_name:<15} UID: {user.pw_uid:<5} Home: {user.pw_dir}")
    
    report("\nGroup Memberships (Sudo/Admin):")
    for group_name in ["sudo", "wheel", "admin"]:
        try:
            g = grp.getgrnam(group_name)
            report(f"  {group_name}: {', '.join(g.gr_mem)}")
        except KeyError:
            pass

def survey_services():
    section("Init System & Services")
    init_type = "Unknown"
    try:
        with open("/proc/1/comm", "r") as f:
            init_name = f.read().strip()
            if init_name == "systemd": init_type = "Systemd"
            elif init_name == "init": init_type = "SysVinit"
    except (PermissionError, FileNotFoundError, OSError): pass
    report("Init System: " + init_type)
    
    if init_type == "Systemd":
        report("\nActive Units (Sample):")
        # In a real stealth survey, we'd avoid spawning 'systemctl'
        # but parsing .service files is very complex. 
        # We will check /etc/systemd/system and /lib/systemd/system/ for existence.
        count = 0
        for root, dirs, files in os.walk("/etc/systemd/system"):
            for name in files:
                if name.endswith(".service"):
                    report("  " + name)
                    count += 1
                if count > 20: break
            if count > 20: break

def survey_firewall():
    section("Firewall Status")

    # iptables — check if kernel module is loaded
    if os.path.exists("/proc/net/ip_tables_targets"):
        report("  iptables: kernel module loaded")
        try:
            with open("/proc/net/ip_tables_targets", "r") as f:
                targets = f.read().strip()
                if targets:
                    report(f"    Targets: {targets}")
        except (PermissionError, FileNotFoundError, OSError):
            pass
    else:
        report("  iptables: not active (module not loaded)")

    # nftables — check if active
    if os.path.exists("/proc/net/nf_tables_names"):
        report("  nftables: active")
        try:
            with open("/proc/net/nf_tables_names", "r") as f:
                names = f.read().strip()
                if names:
                    report(f"    Tables: {names}")
        except (PermissionError, FileNotFoundError, OSError):
            pass
    else:
        report("  nftables: not active")

    # UFW — check config
    ufw_conf = "/etc/ufw/ufw.conf"
    if os.path.exists(ufw_conf):
        report("  UFW: installed")
        try:
            with open(ufw_conf, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ENABLED="):
                        status = line.split("=", 1)[1] if "=" in line else "unknown"
                        report(f"    Status: {'enabled' if status == 'yes' else 'disabled'}")
                        break
        except (PermissionError, FileNotFoundError, OSError):
            report("    (could not read config)")
    else:
        report("  UFW: not installed")

    # firewalld — check config
    firewalld_conf = "/etc/firewalld/firewalld.conf"
    if os.path.exists(firewalld_conf):
        report("  firewalld: installed")
        try:
            with open(firewalld_conf, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Enabled") or ("Enabled" in line and "=" in line):
                        report(f"    {line}")
        except (PermissionError, FileNotFoundError, OSError):
            report("    (could not read config)")
    else:
        report("  firewalld: not installed")


def survey_scheduled_tasks():
    section("Scheduled Tasks")

    # /etc/crontab
    if os.path.exists("/etc/crontab"):
        report("  /etc/crontab:")
        try:
            with open("/etc/crontab", "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        report(f"    {stripped}")
        except (PermissionError, FileNotFoundError, OSError):
            report("    (not readable)")
    else:
        report("  /etc/crontab: not found")

    # /etc/cron.d/
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        try:
            entries = sorted(os.listdir(cron_d))
            if entries:
                report(f"  {cron_d}/:")
                for entry in entries:
                    report(f"    {entry}")
            else:
                report(f"  {cron_d}/: (empty)")
        except (PermissionError, FileNotFoundError, OSError):
            report(f"  {cron_d}/: (not readable)")
    else:
        report(f"  {cron_d}/: not found")

    # /var/spool/cron/crontabs/
    spool = "/var/spool/cron/crontabs"
    if os.path.isdir(spool):
        try:
            entries = sorted(os.listdir(spool))
            if entries:
                report(f"  {spool}/:")
                for entry in entries:
                    report(f"    {entry}")
            else:
                report(f"  {spool}/: (empty)")
        except (PermissionError, FileNotFoundError, OSError):
            report(f"  {spool}/: (not readable)")
    else:
        report(f"  {spool}/: not found or not accessible")

    # systemd timer units
    timer_dirs = ["/etc/systemd/system", "/lib/systemd/system"]
    found_timers = []
    for tdir in timer_dirs:
        if os.path.isdir(tdir):
            try:
                for fname in os.listdir(tdir):
                    if fname.endswith(".timer"):
                        found_timers.append((tdir, fname))
            except (PermissionError, FileNotFoundError, OSError):
                pass

    if found_timers:
        report("  Systemd Timer Units:")
        for tdir, fname in sorted(found_timers):
            report(f"    {tdir}/{fname}")
    else:
        report("  Systemd Timer Units: none found")


def survey_packages_detailed():
    section("Package Management (Detailed)")

    # Read distro info from /etc/os-release
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                distro_name = ""
                distro_version = ""
                for line in f:
                    line = line.strip()
                    if line.startswith("NAME="):
                        distro_name = line.split("=", 1)[1].strip('"')
                    elif line.startswith("VERSION="):
                        distro_version = line.split("=", 1)[1].strip('"')
                if distro_name:
                    ver_str = f" {distro_version}" if distro_version else ""
                    report(f"  Distribution: {distro_name}{ver_str}")
        except (PermissionError, FileNotFoundError, OSError):
            pass

    # DEB packages
    dpkg_status = "/var/lib/dpkg/status"
    if os.path.exists(dpkg_status):
        report("  Package Manager: DEB (Debian/Ubuntu)")
        try:
            with open(dpkg_status, "r") as f:
                content = f.read()
            # Parse package blocks
            pkg_list = []
            for block in content.split("\n\n"):
                pkg_name = ""
                pkg_version = ""
                for line in block.splitlines():
                    if line.startswith("Package: "):
                        pkg_name = line[len("Package: "):]
                    elif line.startswith("Version: "):
                        pkg_version = line[len("Version: "):]
                if pkg_name:
                    pkg_list.append((pkg_name, pkg_version))

            report(f"  Total DEB packages: {len(pkg_list)}")
            report("  First 30 packages:")
            for name, ver in pkg_list[:30]:
                report(f"    {name} {ver}")
            if len(pkg_list) > 30:
                report(f"    ... and {len(pkg_list) - 30} more")
        except (PermissionError, FileNotFoundError, OSError):
            report("  (could not read dpkg status)")

    # RPM packages
    elif os.path.exists("/var/lib/rpm"):
        report("  Package Manager: RPM (RedHat/CentOS/Fedora)")
        rpm_db = "/var/lib/rpm/Packages"
        if os.path.exists(rpm_db):
            try:
                size = os.path.getsize(rpm_db)
                report(f"  RPM Packages DB size: {size} bytes (binary format — count not available without rpm tool)")
            except OSError:
                report("  (could not stat RPM Packages DB)")
        else:
            report("  RPM Packages DB: not found")

    else:
        report("  Package Manager: Unknown (no DEB or RPM detected)")

    # Additional package managers
    extra_managers = {
        "pacman": "/var/lib/pacman",
        "apk": "/etc/apk",
        "portage": "/var/db/pkg/gentoo",
    }
    for name, path in extra_managers.items():
        if os.path.exists(path):
            report(f"  Additional: {name} detected (at {path})")


def survey_security_products():
    section("Security Products")

    # Check for running AV/EDR processes via /proc/*/comm
    target_procs = {
        'clamd', 'freshclam', 'ossec', 'wazuh', 'selinux',
        'auditd', 'fail2ban', 'crowdsec', 'suricata', 'zeek',
    }
    found_procs = {}

    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit()]
        for pid in pids:
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
                    if comm in target_procs:
                        found_procs.setdefault(comm, []).append(pid)
            except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
                continue
    except (PermissionError, FileNotFoundError, OSError):
        pass

    if found_procs:
        report("  Running security processes:")
        for proc_name, pids in sorted(found_procs.items()):
            report(f"    {proc_name}: PID(s) {', '.join(pids)}")
    else:
        report("  No known AV/EDR processes detected running")

    # SELinux check
    selinux_active = False
    # Check /proc/mounts for selinuxfs
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                if "selinuxfs" in line.split():
                    selinux_active = True
                    report("  SELinux: active (selinuxfs mounted)")
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    if not selinux_active and os.path.exists("/etc/selinux/config"):
        try:
            with open("/etc/selinux/config", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SELINUX="):
                        mode = line.split("=", 1)[1] if "=" in line else "unknown"
                        report(f"  SELinux: installed (mode={mode})")
                        selinux_active = True
                        break
        except (PermissionError, FileNotFoundError, OSError):
            pass

    if not selinux_active:
        report("  SELinux: not detected")

    # AppArmor check
    if os.path.exists("/sys/kernel/security/apparmor"):
        report("  AppArmor: active")
    else:
        # Also check /proc/mounts for securityfs + apparmor
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    if "securityfs" in line.split():
                        # securityfs is mounted, check for apparmor subdir
                        # (we already checked the file above; if it doesn't exist, AppArmor not active)
                        break
        except (PermissionError, FileNotFoundError, OSError):
            pass
        report("  AppArmor: not active")


def survey_shell_history():
    section("Shell History (Last 5 Lines per User)")

    history_files = [".bash_history", ".zsh_history", ".python_history"]
    found_any = False

    for user in pwd.getpwall():
        # Only users with real login shells
        if user.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/nologin"):
            continue
        if not user.pw_dir or not os.path.isdir(user.pw_dir):
            continue

        for hist_file in history_files:
            hist_path = os.path.join(user.pw_dir, hist_file)
            if os.path.exists(hist_path) and os.access(hist_path, os.R_OK):
                try:
                    with open(hist_path, "r", errors="replace") as f:
                        lines = f.readlines()
                    if lines:
                        found_any = True
                        last5 = [l.rstrip() for l in lines[-5:] if l.strip()]
                        report(f"  {user.pw_name}: {hist_file} ({len(lines)} lines, showing last 5):")
                        for entry in last5:
                            report(f"    {entry}")
                except (PermissionError, FileNotFoundError, OSError):
                    pass

    if not found_any:
        report("  No readable shell history files found")

def survey_persistence():
    section("Persistence (Cron & Shell)")
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    for path in cron_paths:
        if os.path.exists(path):
            report("Checked Cron Location: " + path)
    
    # Check current user bash history existence
    hist = os.path.expanduser("~/.bash_history")
    if os.path.exists(hist):
        report("Found: .bash_history")

def survey_env_vars():
    section("Environment Variables")
    for k, v in os.environ.items():
        report(f"  {k}={safe_env_value(k, v)}")

def survey_container():
    section("Container & Virtualization Detection")
    if os.path.exists("/.dockerenv"):
        report("  [!] Running inside a Docker container (/.dockerenv found)")
    
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if "docker" in content: report("  [!] Cgroup indicates Docker")
            if "kubepods" in content: report("  [!] Cgroup indicates Kubernetes")
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_kernel_modules():
    section("Loaded Kernel Modules (Sample)")
    try:
        with open("/proc/modules", "r") as f:
            for i, line in enumerate(f):
                if i < 20: report("  " + line.split()[0])
                else:
                    report("  ... more modules loaded")
                    break
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_ssh_analysis():
    section("SSH Analysis")
    # Config check
    if os.path.exists("/etc/ssh/sshd_config"):
        try:
            report("  Checking /etc/ssh/sshd_config:")
            with open("/etc/ssh/sshd_config", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PermitRootLogin") or line.startswith("PasswordAuthentication"):
                        report("    " + line)
        except (PermissionError, FileNotFoundError, OSError): pass
    
    # Authorized keys check
    report("\n  Checking for authorized_keys in /home:")
    try:
        home_base = "/home"
        if os.path.exists(home_base):
            for user_dir in os.listdir(home_base):
                ak_path = os.path.join(home_base, user_dir, ".ssh/authorized_keys")
                if os.path.exists(ak_path):
                    report(f"    [!] Found authorized_keys for user: {user_dir}")
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_arp():
    section("Network Neighbors (ARP Cache)")
    report(pad("IP Address", 20) + pad("HW Type", 10) + pad("Flags", 10) + "HW Address")
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                p = line.split()
                if len(p) >= 4:
                    report(pad(p[0], 20) + pad(p[1], 10) + pad(p[2], 10) + p[3])
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_logs():
    section(f"Recent Logs (Last {config.log_depth} lines)")
    log_file = "/var/log/syslog" if os.path.exists("/var/log/syslog") else "/var/log/messages"
    if os.path.exists(log_file):
        if not os.access(log_file, os.R_OK):
            report(f"[!] Cannot read {log_file} — permission denied.")
        else:
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()[-config.log_depth:]
                for line in lines:
                    report(line.strip())
            except (PermissionError, FileNotFoundError, OSError):
                report("Error reading log file (Permission Denied?)")

def main():
    parser = argparse.ArgumentParser(description='Linux System Survey — Living off the Land')
    parser.add_argument('-o', '--output', default='', help='Output file path (default: survey_<hostname>.txt)'),
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--skip', nargs='*', default=[], help='Module names to skip')
    parser.add_argument('--only', nargs='*', default=[], help='Only run these modules')
    parser.add_argument('--no-hash', action='store_true', help='Skip process hashing (faster)')
    parser.add_argument('--log-depth', type=int, default=300, help='Number of log lines to include')
    args = parser.parse_args()

    if not config.output_file:
        config.output_file = f"survey_{os.uname().nodename}.txt"
    config.output_format = args.format
    config.skip_modules = args.skip
    config.only_modules = args.only
    config.no_hash = args.no_hash
    config.log_depth = args.log_depth

    if os.geteuid() != 0:
        print("WARNING: Script not running as root. The following modules will have limited data:")
        print("  - Processes (limited to current user)")
        print("  - Network (no program names in connections)")
        print("  - Logs (likely permission denied)")
        print("  - SSH config (may be restricted)")
    
    report("Starting Linux System Survey at " + time.ctime())

    ALL_MODULES = [
        ("system_info", survey_system_info),
        ("processes", survey_processes),
        ("network", survey_network),
        ("arp", survey_arp),
        ("users", survey_users),
        ("services", survey_services),
        ("packages", survey_packages_detailed),
        ("firewall", survey_firewall),
        ("scheduled_tasks", survey_scheduled_tasks),
        ("security_products", survey_security_products),
        ("persistence", survey_persistence),
        ("shell_history", survey_shell_history),
        ("env_vars", survey_env_vars),
        ("container", survey_container),
        ("kernel_modules", survey_kernel_modules),
        ("ssh_analysis", survey_ssh_analysis),
        ("logs", survey_logs),
    ]

    # Filter modules based on --skip and --only
    if config.only_modules:
        modules = [(n, f) for n, f in ALL_MODULES if n in config.only_modules]
    else:
        modules = [(n, f) for n, f in ALL_MODULES if n not in config.skip_modules]

    for name, func in modules:
        func()

    # Write output
    with open(config.output_file, "w") as f:
        f.writelines(OUTPUT_BUFFER)

    if config.output_format == 'json':
        json_file = config.output_file.rsplit('.', 1)[0] + '.json'
        with open(json_file, "w") as f:
            json.dump(json_sections, f, indent=2)
        print(f"JSON output saved to {json_file}")

    print(f"\nSurvey complete. Results saved to {config.output_file}")

if __name__ == "__main__":
    main()
