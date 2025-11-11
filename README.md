This is a beginner-friendly SOC Analyst study path, extremely detailed hands-on labs, install steps with “why” comments, and course + certification links for theory in each focus area ; Computer fundamentals, Networking, Security, SIEM/Monitoring, Threat Intel, IR, Vulnerability Management, Cloud Security for AWS, Azure, GCP, Oracle). 

 

Zero-to-SOC Analyst — Full Study Path (with Labs, Installs, Courses & Certs) 

Audience: A true beginner (no prior IT/cyber). 

 Outcome: job-ready Tier-1/Tier-2 SOC skills + portfolio. 

 Duration: ~6 months of part-time (adjust as needed). 

 Structure: Learn → Lab → Reflect (Detection Diary) every week. 

 

Phase 0 — Basecamp Setup (Week 0) 

Workstation & OS 

Laptop/desktop with 16GB RAM (32GB ideal), 200GB free disk. 

CPU virtualization (Intel VT-x/AMD-V) enabled in BIOS. 

Windows 11 + WSL2 (Ubuntu 22.04) or native Ubuntu 22.04. 

 Why: Windows = common endpoint in incidents; Linux = where many security tools run. 

Core Installs (Windows → PowerShell as Administrator) 

# Python (scripting & automation used in many labs) 
winget install Python.Python.3.12 
 
# Visual Studio Code (editor for scripts/configs) 
winget install Microsoft.VisualStudioCode 
 
# Git (version control for your lab notes & code) 
winget install Git.Git 
 
# Windows Subsystem for Linux (Ubuntu for Linux-based tools) 
wsl --install -d Ubuntu 
  

First-run in Ubuntu (from Start menu → “Ubuntu”) 

# Keep the OS patched before installing anything (security best practice) 
sudo apt update && sudo apt upgrade -y 
  

Python starter libs (used across labs) 

# Requests for APIs, pandas/numpy for quick analysis, matplotlib for quick charts 
pip install requests numpy pandas matplotlib 
  

Create a Labs Repo (keeps everything organized) 

# Use either Windows Terminal, PowerShell, or Ubuntu bash 
mkdir -p ~/soc-analyst-labs && cd ~/soc-analyst-labs 
git init 

Month 1 — Computer Fundamentals & Operating Systems (Weeks 1–4) 

Learn (what & why) 

How computers work: CPU, RAM, disks, processes, threads. 

File systems & permissions (Windows vs Linux). 

Command line basics: PowerShell & Bash. 

System services, startup, & logs (Event Viewer, journalctl/syslog). 

Recommended Courses (theory) 

CompTIA ITF+ / Tech+ (new) (foundational computing) — https://www.comptia.org/certifications/itf/ (CompTIA) 

 Note: CompTIA is transitioning ITF+ to Tech+ (see update) — https://www.comptia.org/en-us/blog/get-answers-to-your-comptia-tech-questions/ (CompTIA) 

(Optional & Free) ISC2 Certified in Cybersecurity (CC) self-paced training — https://www.isc2.org/certifications/cc (ISC2) 

Certifications to target (after Month 1) 

ISC2 CC (Entry-level, free training & exam while offer lasts) — https://www.isc2.org/landing/1mcc (ISC2) 

CompTIA ITF+ / Tech+ — https://www.comptia.org/certifications/itf/ (CompTIA) 

Hands-On Labs 

Lab 1 — Windows & PowerShell “Ops Warm-up” 

Goal: learn process/service inspection, log peeking, and evidence capture—skills you’ll use in IR. 

# 1) Create a working folder for artifacts (keeps evidence together) 
New-Item -ItemType Directory -Path "$env:USERPROFILE\Desktop\soclab" -Force 
 
# 2) See CPU-heavy processes (triage often starts here) 
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 
 
# 3) Save a process snapshot to CSV (preserves evidence) 
Get-Process | Export-Csv "$env:USERPROFILE\Desktop\soclab\proc_snapshot.csv" -NoTypeInformation 
 
# 4) Inventory services (malware often uses/abuses services for persistence) 
Get-Service | Sort-Object Status, DisplayName | Out-File "$env:USERPROFILE\Desktop\soclab\services.txt" 
 
# 5) Peek at Security log (100 recent events) — first taste of Windows telemetry 
Get-WinEvent -LogName Security -MaxEvents 100 | 
  Format-Table TimeCreated, Id, LevelDisplayName, ProviderName, Message -Auto 
  

Save outputs in soclab. Write 3 observations (anything odd? repeated logon failures? unknown services?). 

Lab 2 — Linux & Bash “Essentials” 

# 1) Workspace 
mkdir -p ~/soclab/linux_intro && cd ~/soclab/linux_intro 
 
# 2) Baseline the host (you'll use this in IR notes) 
uname -a 
cat /etc/os-release 
 
# 3) Users & groups (understand who can sudo) 
id 
getent group sudo 
 
# 4) Processes & services (spot rogue daemons) 
ps aux | head 
sudo systemctl list-units --type=service --state=running | head -n 20 
 
# 5) Files & permissions (common misconfig vector) 
echo "hello" > sample.txt 
ls -l sample.txt 
chmod 640 sample.txt && ls -l sample.txt 
 
# 6) Logs (starting point for Linux triage) 
sudo tail -n 50 /var/log/syslog 
journalctl -p warning -n 50 
  

Lab 3 — Daily Ops Automation 

# Keep systems patched & log the action — SOC hygiene habit 
cat << 'EOF' > ~/soclab/update_system.sh 
#!/bin/bash 
sudo apt update && sudo apt upgrade -y 
echo "System updated on $(date)" >> ~/soclab/update_log.txt 
EOF 
chmod +x ~/soclab/update_system.sh 
~/soclab/update_system.sh 
  

 

Month 2 — Networking (Weeks 5–8) 

Learn (what & why) 

OSI vs TCP/IP models; IP addressing & subnetting. 

Core protocols: ARP, DHCP, DNS, HTTP(S), SMTP/IMAP, TLS. 

Ports, client/server model, routing vs switching, NAT, firewall basics. 

Recommended Courses (theory) 

CompTIA Network+ (official) — https://www.comptia.org/en-us/certifications/network/ (CompTIA) 

 (Exam details & domains) — https://www.comptia.org/en-us/blog/the-new-network-n10-009-exam-your-questions-answered/ (CompTIA) 

Cisco Networking Academy: Introduction to Networks — https://www.netacad.com/courses/ccna-introduction-networks (Cisco Networking Academy) 

Wireshark Learn (official) — https://www.wireshark.org/learn (Wireshark) 

Certifications to target (after Month 2) 

CompTIA Network+ (great baseline) — https://www.comptia.org/en-us/certifications/network/ (CompTIA) 

Wireshark Certified Analyst (WCNA) (optional, packet-centric) — https://www.wireshark.org/certifications/ (Wireshark) 

Tools to Install 

Wireshark (packet capture & analysis). 

Npcap for Windows capture (bundled in installer). 

VirtualBox to emulate a tiny lab network. 

Hands-On Labs 

Lab 4 — Your First Packet Capture (Wireshark) 

Install Wireshark (include Npcap on Windows). 

Start capture on your active interface. 

Browse to http://example.com and https://example.com. 

Apply filters and explain what you see: 

dns (domain lookups) 

http (clear-text GET; note request/response headers) 

tcp.port == 443 (TLS handshake; you cannot see HTTP content) 

Save as lab4_web_traffic.pcapng and write 5 bullets summarizing DNS→HTTP→TLS flow. 

Lab 5 — Mini-Network & Sniff (Client + Sensor VMs) 

Create two Ubuntu VMs in VirtualBox on an Internal Network (isolated). 

Sensor VM: 

sudo apt update && sudo apt install -y tcpdump 
sudo tcpdump -i eth0 -w /tmp/internal.pcap   # capture background traffic 
  

Client VM: 

curl -I http://example.com   # generate HTTP 
dig example.com              # generate DNS 
  

Stop tcpdump (Ctrl+C); copy internal.pcap to host; open in Wireshark. 

 Explore filters: http, dns, tcp.flags.syn==1 && tcp.flags.ack==0 (new connections). 

Month 3 — Security Fundamentals (Weeks 9–12) 

Learn (what & why) 

CIA triad, threats vs vulnerabilities vs risk; security controls. 

Attacks & malware basics, phishing/social engineering. 

Incident Response lifecycle; MITRE ATT&CK mindset. 

Recommended Courses (theory) 

CompTIA Security+ (official) — https://www.comptia.org/en-us/certifications/security/ (CompTIA) 

 (Exam info) — https://www.comptia.org/certifications/security (CompTIA) 

ISC2 CC (free training) — https://www.isc2.org/certifications/cc (ISC2) 

Certifications to target (end of Month 3) 

ISC2 CC (if not taken earlier) — https://www.isc2.org/landing/1mcc (ISC2) 

CompTIA Security+ — https://www.comptia.org/en-us/certifications/security/ (CompTIA) 

Hands-On Labs 

Lab 6 — Map Observables to MITRE ATT&CK 

Re-open internal.pcap from Lab 5. 

Identify any suspicious patterns (repeated SYNs, odd DNS lookups). 

For each observation, name a likely ATT&CK tactic (e.g., Discovery, C2). 

Add 5 lines to your Detection Diary (what you saw, likely tactic, next data to pull). 

Lab 7 — Create a “Detection Diary” Template 

Create DETECTION_DIARY.md in your repo: 

# Detection Diary 
- Date: 
- Data source (pcap/log): 
- Suspicious observation: 
- Hypothesis (ATT&CK tactic/technique): 
- What data to pull next: 
- Final assessment & recommended control: 
 Month 4 — SIEM & SOC Tooling (Weeks 13–16) 

Learn (what & why) 

SIEM concepts: ingest → normalize → search → alert → tune. 

Windows telemetry (Event IDs, Sysmon), Linux logs. 

Email/URL triage basics (phishing), web attacks (SQLi/XSS) signals. 

Recommended Courses (theory) 

Splunk — Free self-paced intro courses (What is Splunk? Intro to Splunk, Using Fields) — https://www.splunk.com/en_us/training/free-courses/overview.html (Splunk) 

Elastic training (Elastic Stack/Security) — https://www.elastic.co/training (Elastic) 

TryHackMe — SOC Level 1 path — https://tryhackme.com/path/outline/soclevel1 (TryHackMe) 

Certifications to consider 

Splunk Core Certified User (after free courses + practice) — catalog: https://www.splunk.com/en_us/training.html (Splunk) 

Elastic Security (course certificates) — https://www.elastic.co/training (Elastic) 

Hands-On Labs 

Lab 8 — Splunk “Hello Logs” (Single Host) 

Purpose: practice the SIEM loop on a workstation. 

Install Splunk Enterprise (Free) (Windows MSI or Linux DEB). 

Log in at https://localhost:8000. 

Add Data → select Windows Event Logs (Security/System/Application). 

Search for Windows logon failures: 

index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 
| stats count by Account_Name, IpAddress 
| sort - count 
  

Alert: trigger if >10 failures from a single IP in 15 minutes. 

Document in Detection Diary (maps to ATT&CK Credential Access). 

Lab 9 — Basic Phishing Triage 

Save a sample .eml (training sample). 

Extract headers; note From/Reply-To mismatch, SPF/DKIM/DMARC results. 

Build a simple lookup of known bad sender domains (threat_iocs.csv) and enrich email log/search results with lookup in Splunk (join on domain). 

Outcome: first-pass detection content for phishing campaigns. 

Lab 10 — Web Attack Signals in Logs 

Deploy a deliberately vulnerable app in an isolated VM (e.g., DVWA). 

Generate benign & “noisy” requests (SQLi/XSS test strings). 

SIEM searches: 

index=weblogs ("UNION SELECT" OR "<script" OR "%3Cscript") 
| stats count by clientip, uri, useragent 
| sort - count 
  

Turn high-count IPs or patterns into an alert; write mitigations (WAF rules, input validation) in notes. 

 

Month 5 — Cloud Security & Threat Hunting (Weeks 17–20) 

Learn (what & why) 

Cloud shared responsibility, IAM, networking, logging. 

Threat hunting: hypothesis → data sets → queries → findings. 

Cloud Courses & Certifications (pick one platform to start; sample paths below) 

AWS 

AWS Cloud Practitioner (CLF-C02) — https://aws.amazon.com/certification/certified-cloud-practitioner/ (Amazon Web Services, Inc.) 

Free training hub — https://www.aws.training/ (aws.training) 

Exam prep — https://aws.amazon.com/certification/certification-prep/ (Amazon Web Services, Inc.) 

Security Specialty (advanced; later) — https://aws.amazon.com/certification/certified-security-specialty/ (Amazon Web Services, Inc.) 

Microsoft Azure 

AZ-900 Azure Fundamentals — https://learn.microsoft.com/en-us/credentials/certifications/azure-fundamentals/ (Microsoft Learn) 

Study guide — https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/az-900 (Microsoft Learn) 

SC-900 Security, Compliance & Identity Fundamentals — https://learn.microsoft.com/en-us/credentials/certifications/security-compliance-and-identity-fundamentals/ (Microsoft Learn) 

Study guide — https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-900 (Microsoft Learn) 

Google Cloud (GCP) 

Cloud Digital Leader — https://cloud.google.com/learn/certification/cloud-digital-leader (Google Cloud) 

Exam guide — https://cloud.google.com/learn/certification/guides/cloud-digital-leader (Google Cloud) 

Professional Cloud Security Engineer (advanced; later) — https://cloud.google.com/learn/certification/cloud-security-engineer (Google Cloud) 

Oracle Cloud (OCI) 

OCI Foundations Associate — https://education.oracle.com/oracle-cloud-infrastructure-2025-certified-foundations-associate/trackp_OCI25FNDCFA (education.oracle.com) 

OCI Security Professional (2025) — https://education.oracle.com/oracle-cloud-infrastructure-2025-security-professional/pexam_1Z0-1104-25 (education.oracle.com) 

 (Oracle training & certification portal) — https://www.oracle.com/education/certification/ (Oracle) 

Hands-On Cloud Labs 

Lab 11 — AWS S3 “Least Privilege” Guardrails 

Goal: Understand IAM policies & misconfig risks—classic SOC cloud finding. 

In an AWS Free Tier account, create a non-admin IAM user. 

Attach only AmazonS3ReadOnlyAccess. 

Create an S3 bucket; upload a test file. 

Flip the bucket to public (block public access → OFF) and verify outside access; then fix it (block public access → ON). 

Enable CloudTrail; search for the PutBucketPolicy and PutPublicAccessBlock events tied to your change. 

Write controls: S3 Block Public Access org policy, IAM SCPs, Config rules. 

Lab 12 — Threat Hunt: “Success After Failures” 

Hypothesis: an attacker sprayed passwords (many 4625 failures) then succeeded (4624) from the same IP. 

index=wineventlog (EventCode=4625 OR EventCode=4624) 
| eval outcome=if(EventCode==4624,"success","failure") 
| bin _time span=15m 
| stats values(outcome) as outcomes, count as attempts by IpAddress, Account_Name, _time 
| where "failure" in outcomes AND "success" in outcomes AND attempts>10 
  

Action: turn into a detection rule; document false-positive tuning ideas (VPN concentrators, jump hosts). 

 

Month 6 — Capstone, Portfolio & Job Prep (Weeks 21–24) 

Capstone Idea (end-to-end SOC flow) 

Detect brute force → SIEM alert → enrich with a tiny threat-intel CSV → run a response script (disable user/quarantine VM) → document IR timeline & ATT&CK. 

Portfolio Checklist 

GitHub repo with: pcap(s), Splunk saved searches, Suricata/Zeek logs, IR reports, Detection Diary. 

3–5 short write-ups (“How I detected X”, “Hunting Y”). 

Screenshots of dashboards/alerts (sanitize any personal info). 

 

Skill-Area Study Paths (with Focused Labs & Links) 

Each section below maps to typical SOC Analyst responsibilities: Threat Intelligence, Incident Response, Vulnerability Management, Network Security, Security Monitoring/SIEM, Cloud Security, Data Security, Digital Forensics, Security Awareness, Problem-Solving. 

 

1) Threat Intelligence (Beginner) 

Learn: IOC types (IPs/domains/hashes), strategic vs tactical intel, TTPs & MITRE ATT&CK thinking, enriching alerts with intel. 

Courses & Resources 

TryHackMe SOC Level 1 (includes intel & analysis scenarios) — https://tryhackme.com/path/outline/soclevel1 (TryHackMe) 

Mini-Lab — Build a Tiny Threat Feed + SIEM Enrichment 

Create threat_iocs.csv: 

domain,source,first_seen 
badexample[.]com,blog-report,2025-10-01 
  

Upload as a lookup in Splunk. 

Enrich proxy/firewall logs: 

index=proxy OR index=firewall 
| stats count by src_ip, dest_domain 
| lookup threat_iocs.csv domain as dest_domain OUTPUTNEW source, first_seen 
| where isnotnull(source) 
  

Outcome: Any hits are intel-matched traffic → alert & investigate. 

 

2) Incident Response (IR) 

Learn: Detect → Contain → Eradicate → Recover; evidence handling; playbooks & ticketing. 

Courses 

Security+ fundamentals cover IR basics — https://www.comptia.org/en-us/certifications/security/ (CompTIA) 

ISC2 CC (free) for foundational incident concepts — https://www.isc2.org/certifications/cc (ISC2) 

Drill — “Auth Storm” IR 

Detect: Run Month-5 hunt (4625→4624). 

Contain: Disable account or disconnect VM NIC. 

Eradicate: Remove malicious autoruns/services (Get-CimInstance Win32_StartupCommand). 

Recover: Reset password, monitor for recurrence 7 days. 

Report: Timeline, impacted hosts, ATT&CK mapping, lessons learned. 

 

3) Vulnerability Management 

Learn: Scanners (OpenVAS/Greenbone, Nessus), CVSS, exploitability, patch SLAs, exceptions. 

Courses 

General foundations in Network+/Security+. 

(When ready) vendor training (Tenable/Greenbone). 

Lab — OpenVAS Quick Scan 

Install OpenVAS (Greenbone) in a Linux VM. 

Scan your Windows VM; export results. 

Prioritize remediation by risk & exploitability; write a ticket per High/Medium finding with fix steps. 

 

4) Network Security 

Learn: Firewalls, segmentation, IDS/IPS (Suricata/Zeek), traffic analysis. 

Courses 

Cisco Introduction to Networks — https://www.netacad.com/courses/ccna-introduction-networks (Cisco Networking Academy) 

Wireshark WCNA resources — https://www.wireshark.org/certifications/ (Wireshark) 

Lab — Suricata on a Sensor VM 

# Install Suricata IDS and run in AF-PACKET mode on Ubuntu 
sudo apt update && sudo apt install -y suricata 
sudo suricata -i eth0 -l /var/log/suricata 
# Generate “noisy” web requests from a client VM (SQLi/XSS probes). 
# Review /var/log/suricata/fast.log for alerts and ingest into your SIEM next. 
  

 

5) Security Monitoring / SIEM 

Learn: Parsing/normalization, writing SPL/KQL queries, alert logic, tuning & false positives, dashboards. 

Courses 

Splunk Free courses (What is Splunk?, Intro to Splunk, Using Fields) — https://www.splunk.com/en_us/training/free-courses/overview.html (Splunk) 

Elastic training — https://www.elastic.co/training (Elastic) 

Lab — Detect New Local Admins (Windows) 

Create a test local admin. 

Ingest Security logs; search: 

index=wineventlog (EventCode=4720 OR EventCode=4732) 
| stats count by Account_Name, Subject_User_Name, _time 
  

Alert on new users added to admin-equivalent groups; document change-control exceptions. 

 

6) Cloud Security (AWS | Azure | GCP | Oracle) 

Learn: Shared responsibility, IAM, network controls, encryption, logging/monitoring, cloud attack paths. 

AWS 

AWS Cloud Practitioner — https://aws.amazon.com/certification/certified-cloud-practitioner/ (Amazon Web Services, Inc.) 

Training hub — https://www.aws.training/ (aws.training) 

Security Specialty (advanced) — https://aws.amazon.com/certification/certified-security-specialty/ (Amazon Web Services, Inc.) 

Azure 

AZ-900 — https://learn.microsoft.com/en-us/credentials/certifications/azure-fundamentals/ (Microsoft Learn) 

SC-900 — https://learn.microsoft.com/en-us/credentials/certifications/security-compliance-and-identity-fundamentals/ (Microsoft Learn) 

GCP 

Cloud Digital Leader — https://cloud.google.com/learn/certification/cloud-digital-leader (Google Cloud) 

Professional Cloud Security Engineer — https://cloud.google.com/learn/certification/cloud-security-engineer (Google Cloud) 

Oracle (OCI) 

Foundations Associate — https://education.oracle.com/oracle-cloud-infrastructure-2025-certified-foundations-associate/trackp_OCI25FNDCFA (education.oracle.com) 

Security Professional (2025) — https://education.oracle.com/oracle-cloud-infrastructure-2025-security-professional/pexam_1Z0-1104-25 (education.oracle.com) 

Oracle training portal — https://www.oracle.com/education/training/oracle-cloud-infrastructure/ (Oracle) 

Cloud Lab — Azure Sign-in Risk Snapshot 

In an Azure trial, enable Sign-in logs. 

Export to CSV; count failed sign-ins by IP & country. 

Flag unfamiliar geos; write Conditional Access policies (MFA, geo-block). 

Document how you’d monitor with Sentinel/Log Analytics. 

 

7) Data Security 

Learn: Encryption (at rest/in transit), key management, access control, DLP basics, privacy considerations. 

Cloud Lab — S3 Object-Level Controls 

Create a private S3 bucket; enable SSE-KMS (encryption). 

Use IAM Policy Simulator to prove a user without permission cannot access the object. 

Turn on S3 server access logs; search for denied attempts (store in SIEM). 

 

8) Digital Forensics (Intro) 

Learn: Evidence handling, triage collections, hashing, basic reporting. 

Lab — Windows Triage Pack 

Collect: process list, network conns, autoruns, prefetch, recent files. 

Zip & hash (SHA256) the archive; record the hash in your report. 

Write findings with a small timeline. 

 

9) Security Awareness 

Task — 1-Pager “Top 10 Secure Habits” 

Draft for non-technical staff (phishing, MFA, patching, USB hygiene, password managers). 

Share as a PDF in your repo. 

 

10) Problem-Solving & Critical Thinking 

Practice — “Five Whys” on Every Alert 

For any alert, ask “why?” five times to reach a root cause and a preventive control. 

 

Frequently Used Tools — Install Snippets (with “Why” Comments) 

Git, VS Code, WSL, Python (Windows) 

winget install Python.Python.3.12          # scripting 
winget install Microsoft.VisualStudioCode  # editor 
winget install Git.Git                     # version control 
wsl --install -d Ubuntu                    # Linux subsystem for sensors/tools 
  

Linux essentials 

sudo apt update && sudo apt upgrade -y     # patch OS 
pip install requests numpy pandas matplotlib 
  

SIEM Options 

Splunk (Free single host) — https://www.splunk.com/en_us/training/free-courses/overview.html (take “What is Splunk?”, “Intro to Splunk”, “Using Fields”) (Splunk) 

Elastic Stack training — https://www.elastic.co/training (Elastic) 

Endpoint Telemetry (Windows) 

Sysmon (Sysinternals) — enriches process/network events (helps detections). 

Network Telemetry 

# Zeek (network metadata) 
sudo apt update && sudo apt install -y zeek 
sudo zeekctl deploy 
 
# Suricata (IDS/IPS) 
sudo apt install -y suricata 
sudo suricata -i eth0 -l /var/log/suricata 
  

 

Weekly Study Cadence (simple & sustainable) 

Mon–Tue (2h): Theory (pick one course module) → 10 lines of notes. 

Wed–Thu (2–3h): Run a lab and save artifacts (pcap, searches, logs). 

Fri (1h): Update Detection Diary + a short write-up in your repo. 

Weekend (optional): Hands-on path (TryHackMe SOC Level 1). — https://tryhackme.com/path/outline/soclevel1 (TryHackMe) 

 

Certification Roadmap (suggested timing) 

Month 1–2: ISC2 CC (free) and/or CompTIA ITF+/Tech+. 

CC: https://www.isc2.org/certifications/cc (ISC2) 

ITF+/Tech+: https://www.comptia.org/certifications/itf/ (CompTIA) 

Month 2–3: CompTIA Network+ — https://www.comptia.org/en-us/certifications/network/ (CompTIA) 

Month 3–4: CompTIA Security+ — https://www.comptia.org/en-us/certifications/security/ (CompTIA) 

Month 4–5: SIEM vendor basics (Splunk free courses) — https://www.splunk.com/en_us/training/free-courses/overview.html (Splunk) 

Month 5–6: One cloud fundamentals (choose: AWS CLF-C02, Azure AZ-900, GCP CDL, OCI Foundations). 

AWS CLF-C02: https://aws.amazon.com/certification/certified-cloud-practitioner/ (Amazon Web Services, Inc.) 

Azure AZ-900: https://learn.microsoft.com/en-us/credentials/certifications/azure-fundamentals/ (Microsoft Learn) 

GCP CDL: https://cloud.google.com/learn/certification/cloud-digital-leader (Google Cloud) 

OCI Foundations: https://education.oracle.com/oracle-cloud-infrastructure-2025-certified-foundations-associate/trackp_OCI25FNDCFA (education.oracle.com) 

 

Appendix — Extra Study Links 

CompTIA certification catalog: https://www.comptia.org/en-us/certifications/ (CompTIA) 

Network+ overview (what’s on the exam): https://www.comptia.org/en-us/blog/what-is-comptia-network-certification/ (CompTIA) 

Security+ overview: https://www.comptia.org/en-us/blog/what-is-comptia-security-certification/ (CompTIA) 

AWS Cloud Practitioner ramp-up: https://aws.amazon.com/training/learn-about/cloud-practitioner/ (Amazon Web Services, Inc.) 

Azure on-demand AZ-900 modules: https://learn.microsoft.com/en-us/shows/on-demand-instructor-led-training-series/az-900-module-1 (Microsoft Learn) 

SC-900 study guide: https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-900 (Microsoft Learn) 

GCP certifications hub: https://cloud.google.com/learn/certification (Google Cloud) 

Oracle OCI training hub: https://www.oracle.com/education/training/oracle-cloud-infrastructure/ (Oracle) 

Wireshark training (official): https://www.wireshark.org/learn (Wireshark) 

 

How to Use This Document 

Paste into Word. Use Heading 1/2/3 styles for quick navigation and to auto-build a Table of Contents. 

Keep all lab outputs (pcaps, CSVs, screenshots) in your soc-analyst-labs folder and reference them in your Detection Diary. 

When a section feels comfortable, schedule the paired certification (timelines above). 