#!/usr/bin/env python3
import os
import sys
import hashlib
import pwd
import grp
import time
import re

# Configuration
RESULTS_FILE = "survey_results.txt"
LOG_DEPTH = 300
OUTPUT_BUFFER = []

def report(msg):
    print(msg)
    OUTPUT_BUFFER.append(msg + "\n")

def pad(s, length):
    s = str(s)
    return s + " " * (length - len(s))

def section(title):
    border = "################################################################################"
    report("\n" + border)
    report("#  " + title.upper())
    report(border + "\n")

def get_file_md5(path):
    try:
        if not os.path.exists(path): return "N/A"
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return "ERROR"

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
        with open("/proc/cpuinfo", "r") as f:
            count = 0
            for line in f:
                if "processor" in line: count += 1
            report("CPUs: " + str(count))
    except:
        pass

def survey_processes():
    section("Running Processes (with MD5)")
    report(pad("PID", 8) + pad("Name", 25) + pad("MD5", 34) + "Cmdline")
    report(pad("---", 8) + pad("----", 25) + pad("---", 34) + "-------")
    
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
            # To be stealthy, we hash the proc link directly
            md5 = get_file_md5(f"/proc/{pid}/exe")
            
            report(pad(pid, 8) + pad(name[:24], 25) + pad(md5, 34) + cmdline[:100])
        except:
            continue

def survey_network():
    section("Network Configuration")
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:] # Skip headers
            for line in lines:
                parts = line.split(":")
                if len(parts) > 1:
                    report("Interface: " + parts[0].strip())
    except: pass

    section("Active TCP Connections")
    report(pad("Local Address", 25) + pad("Remote Address", 25) + "State")
    try:
        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                local = parts[1]
                remote = parts[2]
                state = parts[3]
                
                # Convert hex IP:Port to human readable
                def parse_addr(addr):
                    ip_hex, port_hex = addr.split(':')
                    ip = ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(len(ip_hex)-2, -1, -2)])
                    port = str(int(port_hex, 16))
                    return f"{ip}:{port}"
                
                report(pad(parse_addr(local), 25) + pad(parse_addr(remote), 25) + state)
    except: pass

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
        except: pass

def survey_services():
    section("Init System & Services")
    init_type = "Unknown"
    try:
        with open("/proc/1/comm", "r") as f:
            init_name = f.read().strip()
            if init_name == "systemd": init_type = "Systemd"
            elif init_name == "init": init_type = "SysVinit"
    except: pass
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

def survey_packages():
    section("Package Management")
    if os.path.exists("/var/lib/dpkg"):
        report("Pkg Manager: DEB (Debian/Ubuntu)")
    elif os.path.exists("/var/lib/rpm"):
        report("Pkg Manager: RPM (RedHat/CentOS/Fedora)")
    else:
        report("Pkg Manager: Unknown")

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
        report(f"  {k}={v}")

def survey_container():
    section("Container & Virtualization Detection")
    if os.path.exists("/.dockerenv"):
        report("  [!] Running inside a Docker container (/.dockerenv found)")
    
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if "docker" in content: report("  [!] Cgroup indicates Docker")
            if "kubepods" in content: report("  [!] Cgroup indicates Kubernetes")
    except: pass

def survey_kernel_modules():
    section("Loaded Kernel Modules (Sample)")
    try:
        with open("/proc/modules", "r") as f:
            for i, line in enumerate(f):
                if i < 20: report("  " + line.split()[0])
                else:
                    report("  ... more modules loaded")
                    break
    except: pass

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
        except: pass
    
    # Authorized keys check
    report("\n  Checking for authorized_keys in /home:")
    try:
        home_base = "/home"
        if os.path.exists(home_base):
            for user_dir in os.listdir(home_base):
                ak_path = os.path.join(home_base, user_dir, ".ssh/authorized_keys")
                if os.path.exists(ak_path):
                    report(f"    [!] Found authorized_keys for user: {user_dir}")
    except: pass

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
    except: pass

def survey_logs():
    section(f"Recent Logs (Last {LOG_DEPTH} lines)")
    log_file = "/var/log/syslog" if os.path.exists("/var/log/syslog") else "/var/log/messages"
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()[-LOG_DEPTH:]
                for line in lines:
                    report(line.strip())
        except:
            report("Error reading log file (Permission Denied?)")

def main():
    if os.geteuid() != 0:
        print("WARNING: Script not running as root. Some information will be missing.")
    
    report("Starting Linux System Survey at " + time.ctime())
    survey_system_info()
    survey_processes()
    survey_network()
    survey_users()
    survey_services()
    survey_packages()
    survey_persistence()
    survey_env_vars()
    survey_container()
    survey_kernel_modules()
    survey_ssh_analysis()
    survey_arp()
    survey_logs()
    
    with open(RESULTS_FILE, "w") as f:
        f.writelines(OUTPUT_BUFFER)
    print(f"\nSurvey complete. Results saved to {RESULTS_FILE}")

if __name__ == "__main__":
    main()
