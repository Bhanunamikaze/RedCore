# RedCore

RedCore is an **advanced Linux privilege-escalation reconnaissance framework** created for Red Team operators and authorised penetration testers.  
It automates the discovery of misconfigurations, vulnerable binaries, weak permissions and novel attack vectors—providing actionable output mapped to the MITRE ATT&CK® framework.

##  Key Features

- **Comprehensive Enumeration**  
  System, kernel, processes, services, network, file-system, sudo rights, cron/systemd timers, capabilities, container & cloud metadata.

- **GTFOBins Integration**  
  Detects exploitable SUID/SGID binaries and offers ready-to-run escalation commands.

- **Cloud & Container Awareness**  
  Identifies AWS/GCP/Azure metadata endpoints, Docker/K8s misconfigurations and escape vectors.

- **Credential Harvesting**  
  Extracts secrets from environment variables, history files, logs, backups and multi-format configs (`.env`, `.json`, `.yml`, …).

- **Rich CLI**  
  Stealth/verbose/quick modes, coloured output, and optional log file generation.

- **MITRE ATT&CK Mapping**  
  Highlights findings against techniques such as `T1068`, `T1548.001`, `T1053.006`, `T1611`, and more.

##  Quick Start

```
git clone https://github.com/Bhanunamikaze/RedCore.git
cd RedCore
chmod +x RedCore.sh
./RedCore.sh -v -o redcore-report.txt
```

Common flags:

| Flag | Long form        | Description                                    |
|------|------------------|------------------------------------------------|
| `-v` | `--verbose`      | Detailed output                                |
| `-s` | `--stealth`      | Minimal writes to disk                         |
| `-q` | `--quick`        | Skip time-consuming checks                     |
| `-o` | `--output FILE`  | Save raw report to `FILE`                      |
| `-h` | `--help`         | Show full usage instructions                   |

##  Sample Output (snippet)

```
[*] ADVANCED SYSTEM RECONNAISSANCE
[!] CRITICAL: Kernel 4.4.0-31-vulnerable to CVE-2017-16995
[>] SUID binary /usr/bin/vim (GTFOBins ➜ :!/bin/sh)
[!] Docker socket writable – container escape possible
[>] Writable systemd timer: /etc/systemd/system/backup.timer
[!] Sensitive credential in .env: DB_PASSWORD=SuperSecret123
```

##  MITRE ATT&CK® Coverage (non-exhaustive)

| Tactic | Technique (ID) | How RedCore Helps Detect It |
|--------|----------------|-----------------------------|
| Privilege Escalation | **Exploitation for Priv-Esc (T1068)** | Kernel CVE checks |
| Privilege Escalation | **Setuid / Setgid (T1548.001)** | SUID/SGID + GTFOBins |
| Persistence / Priv-Esc | **Cron (T1053.003)** | Writable / relative-path cron jobs |
| Persistence / Priv-Esc | **Systemd Timers (T1053.006)** | Timer & service file analysis |
| Defense Evasion / Priv-Esc | **Escape to Host (T1611)** | Docker/K8s escape vectors |
| Credential Access | **Credentials in Files (T1552.001)** | Config / log / backup scanning |

##  Legal Disclaimer

RedCore **must only be used on systems you own or have explicit permission to assess**.  
The authors are **not liable** for misuse or for any damage caused by this tool.  
Using RedCore against targets without consent is illegal.

---

Happy hacking—and always hack **responsibly**!
```
