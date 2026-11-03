# 🛡️ Actionable Threat Intelligence & Detection-as-Code Hub

[![Detection Pack Store](https://img.shields.io/badge/Gumroad-Get_Full_Detection_Packs-ff90e8?style=for-the-badge&logo=gumroad&logoColor=black)](https://YOUR_GUMROAD_LINK)
[![Custom SIEM/EDR Rules](https://img.shields.io/badge/Fiverr-Hire_for_Custom_Rules-1dbf73?style=for-the-badge&logo=fiverr&logoColor=white)](https://YOUR_FIVERR_LINK)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT&CK-v15_Aligned-red?style=for-the-badge)](https://attack.mitre.org/)
[![TLP:CLEAR](https://img.shields.io/badge/TLP-CLEAR-white?style=for-the-badge)](#Attribution--License-TLPCLEAR)

> **Curated by a Senior SecOps & CERT Lead Engineer.**  
> Transforming public Threat Intelligence (OSINT) into production-ready **Sigma Rules**, **Elastic (ES|QL, EQL)**, and **SentinelOne (S1QL)** hunting queries with validated False-Positive filters.

---

## 🔥 Latest Threat Analysis & Back-Data (Updated Weekly)

Every detection rule in this repository is backed by verified OSINT reports and real-world attack artifacts.

### 📌 Case #01: Lumma Stealer & Ransomware Pre-ransom TTPs
* **Original CTI Source:** [The DFIR Report - Analysis Link](https://thedfirreport.com/) *(Published: 2026-11-03)*
* **Targeted MITRE ATT&CK:** `T1059.001` (PowerShell), `T1218.011` (Rundll32), `T1003` (OS Credential Dumping)
* **Attack Summary:** Adversaries utilized obfuscated PowerShell download cradles followed by living-off-the-land binaries (LOLBins) to inject payloads into legitimate Windows processes.

#### 1️⃣ Verified Back-Data (IoCs) — [📁 Download Full CSV](./01_Backdata_IoCs/)
| Indicator Type | Value (Defanged) | Context / Role | Source |
| :--- | :--- | :--- | :--- |
| **SHA256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Initial Dropper DLL | MalwareBazaar |
| **C2 IP** | `198.51.100[.]42:443` | Cobalt Strike C2 Server | ThreatFox |
| **Domain** | `update-win-telemetry[.]com` | Payload Staging Domain | The DFIR Report |

#### 2️⃣ Free Sample Detection Rule — [📁 View Sigma YAML](./02_Free_Sigma_Samples/)
* **Rule ID / Title:** `HIGH_T1059.001_PowerShell_Obfuscated_DownloadCradle_261103`
* **Log Source:** `windows / process_creation` (Sysmon EventID 1)
* **Tuned False Positives:** Excluded legitimate enterprise deployment tools (`SCCM`, `C:\Program Files\Microsoft Monitoring Agent\`).

<details>
<summary><b>🔍 Click to expand converted Elastic (ES|QL) & SentinelOne (S1QL) Queries</b></summary>

**Elastic ES|QL:**
```sql
FROM logs-endpoint.events.process-*
| WHERE host.os.type == "windows"
  AND process.name IN ("powershell.exe", "pwsh.exe")
  AND (process.command_line LIKE "*Invoke-WebRequest*" OR process.command_line LIKE "*-enc*")
  AND NOT process.parent.executable LIKE "C:\\Windows\\CCM\\*"
| STATS count = COUNT(*) BY host.name, user.name, process.command_line



SentinelOne Deep Visibility (S1QL):
EventType = "Process Creation" 
AND SrcProcName In Contains Anycase ("powershell.exe", "pwsh.exe") 
AND (SrcProcCmdLine Contains Anycase "IEX" OR SrcProcCmdLine Contains Anycase "-enc") 
AND NOT (ParentProcImagePath Contains Anycase "C:\Windows\CCM\")

🚀 Upgrade Your SOC: Pro Detection Packs & Custom Engineering
This repository provides 10% free community samples. Need full TTP coverage, pre-built Kibana dashboards, or custom query tuning for your specific enterprise schema?FeatureCommunity Repo (Free)📦 Pro Detection Bundle ($49)🛠️ Custom SecOps Gig (From $100)Curated IoC CSV Feeds✅ Included✅ Automated Weekly Script✅ Custom API IntegrationProduction Sigma Rules1~2 Sample Rules / wk50+ Full TTP RulesetTailored to Your LogsElastic (ES|QL, EQL, KQL)Basic SnippetsFull Query Pack IncludedCustom Index & Field MappingEDR (SentinelOne, Defender)Basic SnippetsFull Hunting Pack IncludedFalse-Positive Exception TuningKibana Dashboard (.ndjson)❌✅ 3 Executive Dashboards✅ Custom Built + Loom GuideAccess LinkYou are here👉 Download on Gumroad👉 Order on Fiverr💼 Need Python SecOps Automation?Looking to automate ThreatFox/MalwareBazaar IoC ingestion, build custom SOAR playbooks, or automate endpoint CLI scanning?📩 Contact for Private Consulting / Retainer: your_business_email@domain.com⚡ Direct Hire via Fiverr / Upwork: View SecOps Automation Services⚖️ Attribution & License (TLP:CLEAR)All Threat Intelligence back-data and IoCs are aggregated from publicly available OSINT sources (TLP:CLEAR). Full credit goes to the original researchers linked in each section.All IP addresses and URLs are defanged ([.], hxxp) to prevent accidental clicks.Detection rules (.yml, queries) in this repository are licensed under the MIT License.
