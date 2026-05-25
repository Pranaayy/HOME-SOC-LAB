# 🛡️ Home SOC Lab — Wazuh SIEM & Sysmon Integration

> **Real-time threat detection, endpoint monitoring, and MITRE ATT&CK-mapped detection engineering in a virtualized enterprise-style SOC environment.**

---

## 📊 Project Metrics

| Metric | Value |
|---|---|
| Total Alerts Generated | 843 |
| Critical Severity Alerts | 36 |
| High Severity Alerts (L12+) | 39 |
| Attack Scenarios Simulated | 4 |
| MITRE ATT&CK Techniques Detected | 5 |
| Monitored Endpoints | 1 (Windows 10) |

---

## 🎯 Objective

Designed and deployed a home Security Operations Center (SOC) environment to simulate enterprise-grade threat detection workflows. The lab demonstrates end-to-end security monitoring — from infrastructure deployment and agent enrollment, through adversarial attack simulation, to alert triage and MITRE ATT&CK mapping.

**Target roles this project supports:** SOC Analyst · Detection Engineer · Security Analyst · Blue Team Analyst

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  VirtualBox Host-Only Network            │
│                     192.168.56.0/24                      │
│                                                          │
│  ┌──────────────────────┐    ┌────────────────────────┐  │
│  │   Ubuntu SIEM Server │    │  Windows 10 Endpoint   │  │
│  │   192.168.56.102     │◄───│  DESKTOP-RBB6U8V       │  │
│  │                      │    │                        │  │
│  │  ┌────────────────┐  │    │  ┌──────────────────┐  │  │
│  │  │ wazuh-manager  │  │    │  │   Wazuh Agent    │  │  │
│  │  │ wazuh-indexer  │  │    │  │   v4.8.0         │  │  │
│  │  │ wazuh-dashboard│  │    │  │   Sysmon         │  │  │
│  │  └────────────────┘  │    │  └──────────────────┘  │  │
│  │  (Docker containers) │    │  (Attack target)        │  │
│  └──────────────────────┘    └────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technologies Used

| Technology | Version | Purpose |
|---|---|---|
| Wazuh | 4.8.0 | SIEM — threat detection, alerting, dashboards |
| Docker | Latest | Containerized Wazuh stack deployment |
| Ubuntu Linux | 22.04 LTS | SIEM server operating system |
| Windows 10 | Pro | Monitored endpoint / attack target |
| Sysmon | Sysinternals | Advanced Windows telemetry collection |
| VirtualBox | Latest | Virtualization platform |
| PowerShell | 5.1 | Attack simulation |

---

## 🚀 Infrastructure Deployment

### Step 1 — Deploy Wazuh Stack (Ubuntu)

```bash
# Clone Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Start Wazuh stack
sudo docker compose up -d

# Verify containers are running
sudo docker ps
```

Expected output: Three containers running — `wazuh-dashboard`, `wazuh-manager`, `wazuh-indexer`

### Step 2 — Install Wazuh Agent (Windows)

Download and install the Wazuh Windows agent, then configure `ossec.conf`:

```xml
<client>
  <server>
    <address>192.168.56.102</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

### Step 3 — Configure Sysmon Integration

Add the following to the Wazuh agent `ossec.conf` to ingest Sysmon telemetry:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## ⚔️ Attack Simulations & Detections

All scenarios were executed on the monitored Windows 10 endpoint and validated against Wazuh alert output.

---

### Scenario 1 — PowerShell Execution Policy Bypass

**MITRE:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | **Tactic:** Execution | **Rule ID:** 92057 | **Severity:** Level 12

```powershell
powershell -ep bypass
```

**What it simulates:** Bypassing PowerShell execution policy — a common first step in malware infection chains and post-exploitation activity.

**Detection:** Wazuh triggered via Sysmon Event ID 1 (Process Creation). Alert captured the `-ep bypass` flag in command-line arguments.

---

### Scenario 2 — Base64 Encoded PowerShell

**MITRE:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | **Tactic:** Execution | **Rule ID:** 92057 | **Severity:** Level 12

```powershell
powershell.exe -EncodedCommand YwBhAGwAYwAuAGUAeABlAA==
```

**What it simulates:** Obfuscated PowerShell execution used in stager payloads and fileless malware to evade signature-based detection. The encoded payload decodes to `calc.exe` (benign stand-in).

**Detection:** Wazuh rule 92057 identified `powershell.exe spawned a powershell process which executed a base64 encoded command`. High-confidence indicator — legitimate scripts rarely require Base64 encoding.

---

### Scenario 3 — Malware-Style Executable File Drop

**MITRE:** [T1105](https://attack.mitre.org/techniques/T1105/) | **Tactic:** Command and Control | **Rule ID:** 92213 | **Severity:** Level 15 (Critical)

```powershell
echo hacked > C:\Windows\Temp\malware_test.exe
```

**What it simulates:** Malware staging behavior — dropping an executable into a high-abuse directory (`C:\Windows\Temp`) during the delivery phase of an attack.

**Detection:** Rule 92213 fired at Critical severity — `Executable file dropped in folder commonly used by malware`. Alert triggered repeatedly across multiple Sysmon Event ID 11 (File Create) entries, demonstrating correlated behavioral detection rather than single-event matching.

---

### Scenario 4 — Persistence via Scheduled Task

**MITRE:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | **Tactic:** Persistence / Privilege Escalation | **Severity:** Medium

```cmd
schtasks /create /sc minute /mo 1 /tn "UpdaterTest" /tr "cmd.exe"
```

**What it simulates:** Establishing persistence by creating a scheduled task that executes `cmd.exe` every minute — one of the most commonly abused Windows persistence mechanisms in real-world threat actor activity.

**Detection:** Windows Event ID 4698 (Scheduled Task Created) captured in Wazuh with persistence and privilege escalation tactic tags.

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Detection Method |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | Sysmon Event ID 1, Rule 92057 |
| T1105 | Ingress Tool Transfer | Command & Control | Sysmon Event ID 11, Rule 92213 |
| T1078 | Valid Accounts | Multiple | Windows Event ID 4624 |
| T1053.005 | Scheduled Task | Persistence | Windows Event ID 4698 |
| T1570 | Lateral Tool Transfer | Lateral Movement | Sysmon network telemetry |

---

## 📸 Screenshots

| Screenshot | Description |
|---|---|
| [`screenshots/01_wazuh_overview.png`](screenshots/01_wazuh_overview.png) | Wazuh overview — 36 critical, 276 medium, 528 low alerts |
| [`screenshots/02_threat_hunting.png`](screenshots/02_threat_hunting.png) | Threat hunting dashboard — 843 total events, MITRE ATT&CK chart |
| [`screenshots/03_security_alerts.png`](screenshots/03_security_alerts.png) | Security alerts table — T1105, T1059.001, T1078 detections |
| [`screenshots/04_powershell_attack.png`](screenshots/04_powershell_attack.png) | PowerShell execution policy bypass on endpoint |
| [`screenshots/05_docker_containers.png`](screenshots/05_docker_containers.png) | Docker stack — all three Wazuh containers active |
| [`screenshots/06_wazuh_agent.png`](screenshots/06_wazuh_agent.png) | Wazuh Agent Manager — DESKTOP-RBB6U8V enrolled and running |

---

## 📁 Repository Structure

```
Home-SOC-Lab/
│
├── screenshots/               # All lab screenshots
│   ├── 01_wazuh_overview.png
│   ├── 02_threat_hunting.png
│   ├── 03_security_alerts.png
│   ├── 04_powershell_attack.png
│   ├── 05_docker_containers.png
│   └── 06_wazuh_agent.png
│
├── configs/                   # Configuration files
│   ├── ossec.conf             # Wazuh agent config (Sysmon integration)
│   └── sysmon-config.xml      # Sysmon monitoring ruleset
│
├── sigma-rules/               # Custom detection rules (coming in Phase 2)
│
├── reports/
│   └── Home_SOC_Lab_Report_Pranay_Nath.docx
│
└── README.md
```

---

## 🔍 Key Findings

- **All 4 attack scenarios were detected** within seconds of execution — zero missed detections across the testing period
- **Critical-severity rules (Level 15)** reliably fired for malware-style file drops, correlated across multiple Sysmon events
- **Encoded PowerShell detection provided high signal quality** — Rule 92057 consistently differentiated obfuscated execution from normal PowerShell activity
- **MITRE ATT&CK auto-tagging** in Wazuh enabled immediate technique classification without manual analyst mapping
- **Authentication noise** (133 successful logon events) identified as a tuning target — would be suppressed or aggregated in a production SOC to reduce alert fatigue

---

## 🔮 Planned Enhancements (Phase 2)

- [ ] Active Directory attack simulation — Kerberoasting, Pass-the-Hash, BloodHound
- [ ] Custom Sigma rules — 10+ rules mapped to MITRE ATT&CK
- [ ] VirusTotal API integration for automated IOC enrichment
- [ ] Suricata IDS for network-layer detection
- [ ] Multi-endpoint monitoring (Linux server + Metasploitable)
- [ ] Python SOAR scripts for automated alert triage
- [ ] AWS CloudTrail + GuardDuty cloud detection lab

---

## 📄 Full Report

A complete professional project report (with embedded screenshots, detection analysis, and analyst observations) is available in [`reports/Home_SOC_Lab_Report_Pranay_Nath.docx`](reports/Home_SOC_Lab_Report_Pranay_Nath.docx)

---

## 👤 Author

**Pranay Nath**
M.S. Cybersecurity | University of North Texas | Expected Dec 2026
OPT/STEM OPT Eligible (3 years, no sponsorship required)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-pranay--nath-blue?logo=linkedin)](https://linkedin.com/in/pranay-nath)
[![Email](https://img.shields.io/badge/Email-nathpranoy%40gmail.com-red?logo=gmail)](mailto:nathpranoy@gmail.com)

---

## 📚 References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Docker Documentation](https://docs.docker.com/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
