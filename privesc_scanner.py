#!/usr/bin/env python3
import subprocess
import os
import datetime

# ─────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout.strip()
    except Exception as e:
        return f"[ERROR] {e}"

def print_section(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

# ─────────────────────────────────────────
# MODULE 1: SYSTEM INFORMATION
# ─────────────────────────────────────────

def system_info():
    print_section("MODULE 1: SYSTEM INFORMATION")
    print(f"Current User   : {run_cmd('whoami')}")
    print(f"User ID Info   : {run_cmd('id')}")
    print(f"Hostname       : {run_cmd('hostname')}")
    print(f"Kernel Version : {run_cmd('uname -r')}")
    print(f"OS Release     : {run_cmd('cat /etc/os-release | grep PRETTY_NAME')}")
    print(f"Uptime         : {run_cmd('uptime -p')}")

# ─────────────────────────────────────────
# MODULE 2: SUID/SGID BINARIES
# ─────────────────────────────────────────

DANGEROUS_SUID = [
    "nmap","vim","vi","find","bash","more","less","nano",
    "cp","mv","awk","perl","python","python3","ruby","lua",
    "tar","zip","unzip","wget","curl","tee","env","cut"
]

def suid_scan():
    print_section("MODULE 2: SUID/SGID BINARY SCAN")
    print("[*] Scanning for SUID binaries (this may take a moment)...")
    output = run_cmd("find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null")
    binaries = output.split("\n") if output else []
    print(f"[*] Total SUID binaries found: {len(binaries)}")
    print("\n[!] HIGH RISK BINARIES (GTFOBins matches):")
    found_risk = False
    for b in binaries:
        name = os.path.basename(b)
        if name in DANGEROUS_SUID:
            print(f"    [HIGH] {b}")
            found_risk = True
    if not found_risk:
        print("    None found.")
    print("\n[*] Full SUID binary list:")
    for b in binaries:
        print(f"    {b}")

# ─────────────────────────────────────────
# MODULE 3: SUDO MISCONFIGURATIONS
# ─────────────────────────────────────────

def sudo_scan():
    print_section("MODULE 3: SUDO MISCONFIGURATION SCAN")
    output = run_cmd("sudo -l 2>/dev/null")
    if output:
        print(output)
        if "NOPASSWD" in output:
            print("\n[!] WARNING: NOPASSWD sudo rule detected — HIGH RISK")
        if "(ALL)" in output:
            print("[!] WARNING: Unrestricted sudo access detected — HIGH RISK")
    else:
        print("    No sudo privileges found or sudo not available.")

# ─────────────────────────────────────────
# MODULE 4: CRON JOB SCAN
# ─────────────────────────────────────────

def cron_scan():
    print_section("MODULE 4: CRON JOB VULNERABILITY SCAN")
    print("[*] System-wide cron jobs:")
    cron_dirs = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                 "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    for path in cron_dirs:
        output = run_cmd(f"ls -la {path} 2>/dev/null")
        if output:
            print(f"\n  {path}:")
            print(f"  {output}")
    print("\n[*] Current user crontab:")
    print(run_cmd("crontab -l 2>/dev/null") or "    No crontab for current user.")
    print("\n[*] Checking for writable cron scripts:")
    output = run_cmd("find /etc/cron* -writable -type f 2>/dev/null")
    if output:
        print(f"[!] WRITABLE CRON FILES DETECTED — HIGH RISK:\n{output}")
    else:
        print("    No writable cron files found.")

# ─────────────────────────────────────────
# MODULE 5: WEAK FILE PERMISSIONS
# ─────────────────────────────────────────

def permission_scan():
    print_section("MODULE 5: WEAK FILE PERMISSION SCAN")
    checks = {
        "/etc/passwd" : "cat /etc/passwd | head -5",
        "/etc/shadow" : "ls -la /etc/shadow 2>/dev/null",
    }
    for label, cmd in checks.items():
        print(f"\n[*] {label}:")
        print(f"    {run_cmd(cmd)}")
    print("\n[*] World-writable files in /etc:")
    output = run_cmd("find /etc -writable -type f 2>/dev/null")
    if output:
        print(f"[!] WORLD-WRITABLE FILES IN /etc — HIGH RISK:\n{output}")
    else:
        print("    None found.")

# ─────────────────────────────────────────
# MODULE 6: KERNEL CVE CHECK
# ─────────────────────────────────────────

VULNERABLE_KERNELS = {
    "5.8.0": "CVE-2021-4034 (PwnKit)",
    "5.4.0": "CVE-2021-4034 (PwnKit)",
    "4.4.0": "CVE-2016-5195 (DirtyCOW)",
    "3.2.0": "CVE-2016-5195 (DirtyCOW)",
}

def kernel_scan():
    print_section("MODULE 6: KERNEL CVE CHECK")
    kernel = run_cmd("uname -r")
    print(f"[*] Kernel version: {kernel}")
    matched = False
    for version, cve in VULNERABLE_KERNELS.items():
        if kernel.startswith(version):
            print(f"[!] VULNERABLE: {cve}")
            matched = True
    if not matched:
        print("[*] No exact CVE match found in local database.")
        print("[*] Always verify against https://cve.mitre.org for your exact kernel.")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def main():
    print("\n" + "#"*60)
    print("#   LINUX PRIVILEGE ESCALATION SCANNER")
    print("#   Project 6 — Cybersecurity Scholarship")
    print(f"#   Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("#"*60)

    system_info()
    suid_scan()
    sudo_scan()
    cron_scan()
    permission_scan()
    kernel_scan()

    print("\n" + "#"*60)
    print("#   SCAN COMPLETE")
    print("#"*60 + "\n")

if __name__ == "__main__":
    main()
