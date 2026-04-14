# threat-hunting-scenario-tor# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MichaelSarete/threat-hunting-scenario-tor/blob/main/hreat-hunting-scenario-tor-event-creation)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for Any file that contains the string “tor” in it and discover what looks like the user “employee” downloaded a Tor installer, did something that resulted in many Tor-related files being copied to the desktop, and created a file called “Tor-Shopping-List.txt” on the desktop. These events began at: 2026-04-09T00:37:36.0044046Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "wind11"
| where InitiatingProcessAccountName =="ehi"
|where  Timestamp >= datetime(2026-04-09T00:37:36.0044046Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath,SHA256, Account = InitiatingProcessAccountName
|order by Timestamp desc

```
<img width="1897" height="796" alt="Image" src="https://github.com/user-attachments/assets/53166449-26df-4ac6-a05e-cc3db4417e91" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-15.0.9.exe” based on the log returned  At 2026-04-09T00:39:03.6520972Z, a user named ‘ehi’ on the computer ‘wind11’ launched a file called ‘tor-browser-windows-x86_64-portable-15.0.9.exe’, starting the installation or execution of the Tor Browser on that machine.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where  DeviceName == "wind11"
|where  ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine

```
<img width="1897" height="796" alt="Image" src="https://github.com/user-attachments/assets/07f4be0e-528e-4cc4-bdb8-028dca7b7ce7" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search the DeviceProcessEvents table for any indication that the user ”ehi” actually opened the Tor browser. There was evidence that they did open it at 2026-04-09T00:39:22.3314782Z

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "wind11"
| where FileName has_any("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType,FileName, FolderPath,ProcessCommandLine, SHA256
| order by Timestamp desc 
```
<img width="1850" height="822" alt="Image" src="https://github.com/user-attachments/assets/7c5912a8-ad42-4841-9317-91865dc36615" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvent table for any indication that the Tor Browser was used to establish a connection using any of the known ports. At 2026-04-09T00:39:25.0779739Z, the user ‘ehi’ on the computer ‘wind11’ successfully made a secure internet connection to the website ‘https://www.t2onw.com’ using the program ‘tor.exe’, communicating over port 443 (the same port normally used for HTTPS traffic).


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where  DeviceName == "wind11"
| where InitiatingProcessAccountName != "system"
| where RemotePort in  ("9001","9030","9050","9051","9150","9151","9040","9060","443","80")
| where InitiatingProcessFileName  has_any("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
|order by Timestamp desc

```
<img width="1888" height="642" alt="Image" src="https://github.com/user-attachments/assets/fda677ce-dac2-44ac-afe3-1aadd66bb17c" />

---

## Chronological Event Timeline

### 🕵️‍♂️ Threat Timeline Report: Tor Browser Usage
🖥️ Host: wind11
👤 User: ehi
📅 Date: April 8, 2026


### ⏱️ Phase 1: Initial Tor-Related File Activity (Download & File Creation)
8:37:36 PM – 8:37:40 PM
The first indicators of Tor-related activity begin.
Multiple file events show Tor-related files being introduced into the system.
Activity suggests:
Initial download or staging of Tor components
Files associated with Tor begin appearing on the system

8:39:11 PM – 8:39:15 PM
Increased file activity involving Tor-related files.
Multiple entries indicate:
File creation and/or modification
Possible unpacking or preparation of the Tor portable package

8:39:23 PM – 8:39:25 PM
Additional Tor-related files appear on disk.
Likely actions:
Extraction of files from the portable installer
Setup of runtime environment for execution



### ⚙️ Phase 2: Execution of Tor Installer
8:39:03 PM
The user executes:

 tor-browser-windows-x86_64-portable-15.0.9.exe


This marks:
Start of Tor Browser installation or portable execution
Initiation of Tor environment on the host

### 🚀 Phase 3: Tor Browser Launch & Process Activity
8:39:22 PM
Evidence confirms the user launched Tor Browser components:
tor.exe
firefox.exe (Tor Browser frontend)
This indicates:
Successful execution of Tor Browser
Browser environment fully initialized

8:39:22 PM – 8:41:59 PM
Numerous process creation events observed:
Repeated spawning of Tor-related processes
This behavior is consistent with:
Tor’s multi-process architecture
Circuit building and background service initialization


### 🌐 Phase 4: Network Activity via Tor
8:39:25 PM
A network connection is established:
Process: tor.exe
Destination URL: https://www.t2onw.com
Port: 443 (HTTPS)
This confirms:
Active Tor network usage
Encrypted outbound communication through Tor


### 📂 Phase 5: Continued File Activity (Post-Execution)
8:51:51 PM – 8:56:08 PM
Additional file operations involving Tor-related artifacts:
Likely user interaction with Tor files
Possible file movement or additional downloads

9:43:04 PM
Final observed Tor-related file activity:
Indicates continued interaction with Tor-related files well after initial execution

---

## Summary

The user "Ehi" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and create various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `wind11` by the user `ehi`. The device was isolated, and the user's direct manager was notified.

---
