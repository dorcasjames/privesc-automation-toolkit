# Linux Privilege Escalation Automation Toolkit

A Python-based automated scanner that detects privilege escalation vulnerabilities on Linux systems. Built as part of a Cybersecurity Scholarship program.

## What It Does
Scans a live Linux system across six modules and generates a structured findings report — detection only, no exploitation.

## Modules
- Module 1: System Information Collection
- Module 2: SUID/SGID Binary Discovery
- Module 3: Sudo Misconfiguration Detection
- Module 4: Cron Job Vulnerability Scan
- Module 5: Weak File Permission Analysis
- Module 6: Kernel CVE Check

## Usage
```bash
python3 privesc_scanner.py
Environment
Built and tested on Kali Linux
Python 3.x required
Author
Adebamigbe Dorcas Adeyemi
Cybersecurity Scholarship Student
GitHub: github.com/dorcasjames
Disclaimer
This toolkit is for educational and authorized auditing purposes only.
