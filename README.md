<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-05T19:08:40.4518135Z`. These events began at `2025-08-05T18:49:02.6081288Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
 | where FileName contains "tor" 
 | where InitiatingProcessAccountName == "labuser22”
 | where DeviceName == "malc-mde-test" 
 | where Timestamp >=  datetime(2025-08-05T18:49:02.6081288Z)
 | order by Timestamp desc 
 | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1184" height="236" alt="image" src="https://github.com/user-attachments/assets/16ca06e5-1332-45f2-bce7-7e11e9cd88fe" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-08-05T18:51:40.9701624Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents 
| where DeviceName == "malc-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe" 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1412" height="200" alt="image" src="https://github.com/user-attachments/assets/84d80b91-65fc-40dd-804c-a83778b58a33" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-08-05T18:52:54.8289683Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
 | where DeviceName == "malc-mde-test"
 | where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
 | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
 | order by Timestamp desc

```
<img width="1330" height="267" alt="image" src="https://github.com/user-attachments/assets/1f89ca00-bca7-4837-b68c-44e9375b5556" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-08-05T18:53:29.6149285Z`, an labuser22 on the "malc-mde-test" device successfully established a connection to the remote IP address `185.162.250.173` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\labuser22\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
 DeviceNetworkEvents
 | where DeviceName == "malc-mde-test" 
 | where InitiatingProcessAccountName != "system" 
 | where RemotePort in ("9001", "9030", "9040", "9050","9051" "9150") 
 | project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
 | order by Timestamp desc
 
```
<img width="1002" height="242" alt="image" src="https://github.com/user-attachments/assets/bef45096-f7ad-4bd2-bfa1-be256e3ecccb" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-05T18:52:25.3159386Z`
- **Event:** The user "labuser22" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-05T18:51:40.9701624Z`
- **Event:** The user "labuser22" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\labuser22\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-05T18:52:54.8289683Z`
- **Event:** User "labuser22" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser22\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-05T18:53:29.0895746Z`
- **Event:** A network connection to IP `185.162.250.173` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\users\labuser22\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-05T18:53:26.4912791Z` - Connected to `135.148.171.158` on port `443`.
  - `2025-08-05T18:53:56.6022135Z` - Local connection to `78.46.92.172` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-05T19:08:40.4518135Z`
- **Event:** The user "labuser22" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser22\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser22" on the "malc-mde-test” device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named “tor-shopping-list. txt” . This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.


---

## Response Taken

TOR usage was confirmed on endpoint malc-mde-test. The device was isolated and the user's direct manager was notified.

---
