#  Digital Forensics Investigation Report  
**Case Study: TAAUSAI4 Food Services, New York, USA**

---

##  Executive Summary
On **March 22, 2019**, a Windows 10 Pro (Build 1709) workstation at **TAAUSAI4 Food Services** was compromised through a **phishing-based social engineering attack**.  
The user, *Karen*, was tricked into clicking a malicious link while job hunting, which led to the download and execution of a Trojan-laced file named **antimalwaresetup.exe**.  
The file was later found in the system’s Recycle Bin. The attack involved external coordination, potential credential theft, and attempted evasion.  
A full forensic investigation was conducted to determine the scope, attack vector, and legal artifacts of the compromise.

---

##  Company Background

| Attribute       | Details                          |
|-----------------|----------------------------------|
| Name            | TAAUSAI4 Food Services           |
| Location        | New York, USA                    |
| Industry        | Catering & B2B Food Services     |
| IT Environment  | Legacy Windows                   |
| Client Base     | Finance, Law, and Hospitality    |

---

##  Investigation Objectives
- Confirm presence and origin of malware  
- Identify persistence mechanisms and lateral movement  
- Recover and analyze email evidence  
- Build a timeline of the attack  
- Produce legally defensible artifacts and IOCs  

---

##  Tools & Methodology

| Phase              | Tools Used                                      |
|--------------------|-------------------------------------------------|
| Imaging            | FTK Imager (E01 format, MD5/SHA1 hashes)        |
| Registry Analysis  | Registry Editor (offline hives)                 |
| Mailbox Analysis   | Kernel OST Viewer                               |
| Timeline & IOC     | VirusTotal                                      |

---

##  Key Findings

### Initial Compromise
- **User:** Karen  
- **Browser:** Google Chrome  
- **Date:** 22/03/2019    
- **Downloaded File:** `antimalwaresetup.exe`  
- **VirusTotal Result:** Confirmed Trojan  

### Disk Evidence
- **System:** Windows 10 Pro (Build 1709)  
- **Disk:** 2 partitions  
- **Malware Location:** Recycle Bin on Partition 2  
- **Inference:** Attempted deletion or self-cleanup by malware  

### Social Engineering & Coordination
- Karen was coached by external actors to gain Bob’s trust  
- Received GPS coordinates pointing to Egypt  
- Sent a WinRAR archive containing chat logs with Bob  
- **Password:** `paclove`  

---

##  Behavioral & Technical Analysis

### Registry Artifacts
- No Registry changes found  
- Possible alteration or deletion of traces by attackers  
- Malicious activity confirmed via other evidence  
- Next steps: memory, logs, and network analysis  

### Mailbox Artifacts
- OST files extracted and reviewed  
- No direct phishing email recovered  
- Timeline aligns with browser activity  
- Email headers and attachments preserved for legal review  

### Timeline Reconstruction
- Malware execution: **22/03/2019**  
- Recycle Bin deletion: Shortly after execution  
- No lateral movement beyond local machine  

---

##  Chain of Custody Summary

| Item                  | Evidence | MD5 Hash | SHA1 Hash | Acquired By | Date       | Storage              | Transfers |
|-----------------------|----------|----------|-----------|-------------|------------|----------------------|-----------|
| Windows Disk Image (E01) | e0a092672ef54b8e88481db0eaa17c9f | 17ea7a5c5517c8a3c38224df4cc03fa66b08edd6 | NIL | 20/11/2025 | Forensic Workstation | Logged and signed |

---

##  Indicators of Compromise (IOCs)

| Type   | Value                          |
|--------|--------------------------------|
| File   | `antimalwaresetup.exe`         |
| SHA-256| 8226266af9a324badf0af79158f115fa5b35ca673f1ca8679c6e0e8051b981a0 |
| Domain | `chromeExtmalware.Store`       |

---

##  VirusTotal Threat Intelligence Summary

| Attribute | Value |
|-----------|-------|
| File Name | `antimalwaresetup.exe` |
| SHA-256   | 8226266af9a324badf0af79158f115fa5b35ca673f1ca8679c6e0e8051b981a0 |
| MD5       | baf4efe35aa11d7d387824ce7925b7a6 |
| SHA-1     | abead8752ef9a4da8baf4698e734de93fa35782e |

**Detection:**  
- Detected by 50+ antivirus engines  
- Labels: Trojan.Generic, Trojan.Injector, Win32:Malware-gen, Malicious.Behavior  

**Behavioral Indicators:**  
- Downloads additional payloads  
- Injects into other processes  
- Establishes remote connections (C2)  

**Network Indicators:**  
- Suspicious domains/IPs  
- HTTP POST exfiltration  

**File Characteristics:**  
- Packed executable  
- Drops additional files  
- Attempts privilege escalation  

---

##  Recommendations

### Immediate Actions
- Isolate affected system  
- Reset all user credentials  
- Block `chromeExtmalware.Store` and related IPs  
- Review WinRAR archive contents for legal escalation  

### Long-Term Improvements
- Patch or migrate legacy systems  
- Deploy EDR and centralized logging  
- Conduct phishing awareness training  
- Implement stricter email filtering and sandboxing  

---

##  Acknowledgment
**Prepared by:** Adams Samson  
**Date:** November 20, 2025  

 Connect with me on [LinkedIn](https://www.linkedin.com/in/adams-samson)

Thank you for your time.
Thank you for your time.
