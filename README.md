<img width="500" height="150" alt="image" src="https://github.com/user-attachments/assets/a6da6b0a-4369-4a11-ae42-5e58c3525edf" />



# Threat Hunt Report (Azuki Import/Export - 梓貿易株式会社)

## Scenario:
[Scenario Creation](https://github.com/jfsaravia/Threat-hunt-Azuki-Import-Export/blob/main/Azuki-Scenario.md)

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

**COMPANY:**

Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

**COMPROMISED SYSTEMS:**

AZUKI-SL (IT admin workstation)

---

## High-Level IoC Discovery Plan:

1. Check DeviceProcessEvents for any **DeviceName == "**azuki-sl**"**
2. Check DeviceProcessEvents for any signs of installation or usage
3. Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports

---

# Steps Taken

## 1. Discovering Malicious IP address ( DeviceLogonEvents)

On Nov 19, 2025, at 18:36 UTC (6:36 pm), an RDP session was established from external IP 88.97.178.12 to azuki-sl under user kenji.sato. Sequence shows initial authentication attempts followed by successful Network and RemoteInteractive logons, indicating external remote access.

### KQL Query used (MaliciousIP)

```sql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
  and Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
  and AccountName contains "kenji"
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType , FailureReason, RemoteIP, InitiatingProcessRemoteSessionDeviceName
```

[<img width="1722" height="547" alt="image" src="https://github.com/user-attachments/assets/c05f0bd8-e748-4cb7-9df8-605d1eeae425" />
](https://www.notion.so/image/attachment%3A292b5450-97aa-4ae6-957c-28b04658f36b%3Aimage.png?table=block&id=2c4fc6f5-ad50-8035-9010-c8cff7252b18&spaceId=a1cdf9f6-20a4-48a7-83c7-eb73c6331a27&width=2000&userId=c77bd267-6a8b-4ad9-9d15-5d212bad7d26&cache=v2)

## 2. Compromised account

On November 19, 2025, 6:36 pm UTC, the external IP address **88.97.178.12** successfully authenticated to the **kenji.sato** account on host *azuki-sl*. This confirms that the credentials for **kenji.sato** were compromised and used by an unauthorized party.
 

### KQL Query used ( CompAcc):

```sql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| extend ClientIP = coalesce(RemoteIP, InitiatingProcessRemoteSessionIP)
| where ClientIP == "88.97.178.12"
| project Timestamp, AccountName, ActionType, LogonType, ClientIP
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/b31d4652-07d2-4e8e-94fe-f68130bbf5be)


## 3. Network Enumeration

On November 19, 2025, at 19:04 UTC (7:04 pm), when first gaining access, the account kenji.sato executed the command `arp -a` via PowerShell on host *azuki-sl*. This command enumerates the local ARP cache to identify IP-to-MAC address mappings of devices on the local network, indicating local network discovery activity following successful access.

<img width="1478" height="692" alt="image" src="https://github.com/user-attachments/assets/6515262d-ac52-403e-81da-f7ac879c9d0d" />


### KQL Query used :

```sql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
and AccountName == "kenji.sato"
and TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
and InitiatingProcessFileName == "powershell.exe"
and ProcessCommandLine has_any ("arp", "ipconfig", "-a")
| order by TimeGenerated asc 
| project TimeGenerated, AccountName, DeviceName, ActionType, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 4. Malware staging directory

On November 19, 2025, the attacker using the compromised kenji.sato account on azuki-sl created and hid the directory C:\ProgramData\WindowsCache at 19:03 UTC (7:03 pm) using attrib.exe +h +s. Immediately after, at 19:03–19:04 UTC (7 pm), they downloaded two malicious files from [http://78.141.196.6:8080](http://78.141.196.6:8080/) into this hidden folder using certutil.exe. At 19:04 UTC (7:04 pm), they established persistence by creating a scheduled task (“Windows Update Check”) that executed a file from the same directory. Shortly after, they attempted data exfiltration at 19:04 UTC by uploading export-data.zip from WindowsCache via curl.exe. These events show that C:\ProgramData\WindowsCache was used as the attacker’s staging location for tools and exfiltration.

<img width="1790" height="701" alt="image (1)" src="https://github.com/user-attachments/assets/e1790f43-2c4b-4cc5-b387-c7531d87f722" />


### KQL Query Used:

```sql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
and AccountName == "kenji.sato"
and TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
and InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("C:\\ProgramData\\WindowsCache")
| order by TimeGenerated asc 
| project TimeGenerated, AccountName, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
```

## 5. Defense Evasion

On 2025-11-19, around 18:49 UTC (6:49 pm), Windows Defender extension exclusions were added on azuki-sl for .exe, .ps1, and .bat, indicating defense evasion by reducing antivirus scanning coverage.

<img width="1447" height="463" alt="image (2)" src="https://github.com/user-attachments/assets/071f21c7-cc99-4578-8660-0cf668ccd213" />


### KQL Query Used:

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
    and DeviceName == "azuki-sl"
| where RegistryKey has @"\Microsoft\Windows Defender\Exclusions\Extensions"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName
```

## 6. Impaired Defences; Disable or Modify Tools

On November 19, 2025, around 18:49 UTC (6:49 pm), path exclusions were added to Windows Defender on *azuki-sl* for *C:\ProgramData\WindowsCache* and the user’s Temp directory, indicating defense evasion to avoid antivirus scanning.

<img width="1463" height="395" alt="image (3)" src="https://github.com/user-attachments/assets/e43d46a6-eb12-477a-a0d4-873b9469b75c" />


### KQL Used:

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
    and DeviceName == "azuki-sl"
    and RegistryValueName contains "C:"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName
```

## 7. LOTL Defence Evasion

On **November 19, 2025**, at 7:07 pm UTC,  the attacker used **certutil.exe** via **PowerShell** on *azuki-sl* under the *kenji.sato* account to download external executables into *C:\ProgramData\WindowsCache*, indicating a **living-off-the-land** technique for malicious file transfer and defense evasion.

<img width="2343" height="370" alt="image (4)" src="https://github.com/user-attachments/assets/1ac261dc-ad3b-4b60-8d08-22bf19a76b57" />


### KQL used:

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
    and DeviceName == "azuki-sl"
    and AccountName == "kenji.sato"
    and ProcessCommandLine has_any ( "certutil")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    AccountName,
    ProcessCommandLine,
    FileName,
    InitiatingProcessParentFileName

```

## 8. **PERSISTENCE - Scheduled Task Name**

On **November 19, 2025**, 7:07 pm UTC,  the attacker used **schtasks.exe** via **PowerShell** on *azuki-sl* under the *kenji.sato* account to create and query a scheduled task (“Windows Update Check”) that executed a malicious file from ***C:\ProgramData\WindowsCache***, indicating **persistence via Task Scheduler**.

<img width="2273" height="420" alt="image (5)" src="https://github.com/user-attachments/assets/ebf42ca7-9e50-481c-9a0c-83c2fb9b0653" />



### KQL

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
    and DeviceName == "azuki-sl"
    and AccountName == "kenji.sato"
    and ProcessCommandLine has_any ( "schtasks.exe")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    AccountName,
    ProcessCommandLine,
    FileName,
    InitiatingProcessParentFileName
```

## 9. C2 Server Address (Command & Control)

On **November 19, 2025**, at 7:06 pm UTC, the attacker used **certutil.exe** on *azuki-sl* under the *kenji.sato* account to establish a successful outbound connection to the **public IP 78.141.196.6 over port 8080**, indicating communication with an external **command-and-control (C2) server** for payload retrieval.

<img width="2315" height="497" alt="image (6)" src="https://github.com/user-attachments/assets/dc9c0bd9-1a5a-4076-9659-06bd487874b4" />


### KQL Used:

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-11-30))
    and DeviceName == "azuki-sl"
    and InitiatingProcessAccountName == "kenji.sato"
    and InitiatingProcessCommandLine contains "certutil.exe"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemoteIPType, RemotePort, InitiatingProcessFolderPath
```

## 10.  C2 Communication report

On **November 19, 2025**, 7:11 pm UTC, a malicious executable located in **C:\ProgramData\WindowsCache** on *azuki-sl* established a successful outbound connection to the public IP **78.141.196.6** over **port 443**, indicating **command-and-control (C2) communication** originating from the attacker’s staged payload.

<img width="1555" height="591" alt="image (7)" src="https://github.com/user-attachments/assets/59adb7fa-10ad-47d8-a6f4-684d1be4abbe" />


### KQL used:

```sql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath has "C:\\ProgramData\\WindowsCache"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteIPType, ActionType
| order by TimeGenerated asc
```

## 11. Credential Access (Credential Theft Tool)

On **November 19, 2025**, at 7:07 pm UTC, the attacker staged a **renamed credential-dumping tool (`mm.exe`)** in the directory **C:\ProgramData\WindowsCache** on *azuki-sl*. The short, non-descriptive filename and placement in a hidden staging directory indicate an attempt to evade detection and facilitate **credential dumping via LSASS memory access**.

<img width="1465" height="623" alt="image (8)" src="https://github.com/user-attachments/assets/2a4d5ed3-b817-48c1-8fd4-3d3d9e5a70d8" />


### KQL Used:

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName == "azuki-sl"
| where FolderPath has "C:\\ProgramData\\WindowsCache"
| where FileName endswith ".exe"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```

## 12. Credential Access  **Memory Extraction Module**

On November 19, 2025, at 7:08 pm UTC, the attacker executed a renamed credential-dumping tool (mm.exe) on azuki-sl using the `sekurlsa::logonpasswords` module, confirming LSASS memory access to extract stored credentials.

<img width="847" height="242" alt="image (10)" src="https://github.com/user-attachments/assets/9385eb10-7d3b-4878-b21f-7132677bc14f" />



### KQL Used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has "mm.exe"
   or InitiatingProcessCommandLine has "mm.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

## 13. **COLLECTION - Data Staging Archive**

On November 19, 2025, at 7:09 pm UTC, the attacker used curl.exe on azuki-sl to upload the archive export-data.zip to an external Discord webhook URL, indicating staged data collection and outbound exfiltration.

<img width="724" height="238" alt="image (11)" src="https://github.com/user-attachments/assets/5c2a9943-ac7f-4f5c-a7ba-f5ab91e79018" />


### KQL used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("curl.exe", "export-data.zip") 
   or InitiatingProcessCommandLine has_any ("curl.exe", "export-data.zip")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

## 14. **EXFILTRATION - Exfiltration Channel**

On November 19, 2025, at 7:09 pm UTC, the attacker used curl.exe under the compromised account kenji.sato on azuki-sl to upload the archive export-data.zip to an external Discord webhook, confirming outbound data exfiltration to attacker-controlled infrastructure.

<img width="902" height="260" alt="image (12)" src="https://github.com/user-attachments/assets/065b4c50-bfa1-458b-9887-f0a7a6b91254" />


### KQL Used:

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
and DeviceName == "azuki-sl"
and InitiatingProcessAccountName == "kenji.sato"
and InitiatingProcessCommandLine has_any ("certutil.exe", "export-data.zip") 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemotePort,LocalIP, LocalPort, Protocol
| order by TimeGenerated asc
```

## 15. **ANTI-FORENSICS - Log Tampering**

On November 19, 2025, at 7:11 PM UTC, the attacker executed wevtutil.exe with the command `cl Security on azuki-sl`, clearing the Windows Security event log to remove evidence of prior malicious activity.

<img width="748" height="296" alt="image (13)" src="https://github.com/user-attachments/assets/23452573-5759-4762-b492-da54a9a9865d" />


### KQL used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("wevtutil.exe") 
   or InitiatingProcessCommandLine has_any ("wevtutil.exe", "archive-log")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```

## 16. **IMPACT - Persistence Account**

On November 19, 2025, at 7:09 pm UTC, the attacker created a local user account named support on azuki-sl and added it to the local Administrators group using the commands `net user support /add` and `net localgroup Administrators support /add`, establishing persistent administrative access for future use.

<img width="893" height="318" alt="image (14)" src="https://github.com/user-attachments/assets/c7c0c0d8-1f5d-4b1e-849d-d598ed861e07" />


### KQL used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
    and AccountName == "kenji.sato"
| where ProcessCommandLine has_any ("/add", "New-LocalUser", "-Name", "-password", "administrator") 
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc

```

## 17. **EXECUTION - Malicious Script**

On November 19, 2025, the attacker executed a malicious PowerShell script named wupdate.ps1 on azuki-sl using the command `powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File wupdate.ps1`, automating multiple stages of the attack while bypassing PowerShell security controls.

<img width="893" height="318" alt="image (15)" src="https://github.com/user-attachments/assets/c4901fad-487f-431b-ac9e-db66ee0b15ee" />


KQL Used: 

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
    and InitiatingProcessCommandLine contains "powershell"
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    FileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```

## 18. **LATERAL MOVEMENT - Secondary Target**

On November 19, 2025, between 7:10 pm and 4:06 am UTC, the attacker used the IP address 10.1.0.188 for lateral movement by storing credentials with `cmdkey.exe /generic:10.1.0.188 /user:<username> /pass:<password>` and initiating remote desktop connections using `mstsc.exe /v:10.1.0.188`, indicating authenticated RDP access to another internal system.

<img width="1752" height="622" alt="image (16)" src="https://github.com/user-attachments/assets/f76035b8-6be9-4e4a-99dc-f56c02a01753" />


### KQL Used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
    and AccountName == "kenji.sato"
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc

```

## 19. **LATERAL MOVEMENT - Remote Access Tool**

On November 19, 2025, at 6:33 pm UTC, the attacker used the built-in Remote Desktop client mstsc.exe on azuki-sl to initiate lateral movement by connecting to the internal system at 10.1.0.188, leveraging native administrative tooling to blend in with legitimate activity.

<img width="877" height="317" alt="image (17)" src="https://github.com/user-attachments/assets/8e47ae54-e4f0-4a98-8235-64e4b2bb1230" />


### KQL used:

```sql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
    and AccountName == "kenji.sato"
| where ProcessCommandLine has_any ("mstsc")
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc

```

---

---

## Chronological Events

1. On November 19, 2025, external IP address 88.97.178.12 successfully authenticated to azuki-sl via RDP using the compromised account kenji.sato.
2. Shortly after access, the attacker performed network enumeration using arp -a to identify internal systems.
3. The attacker created and hid the directory C:\ProgramData\WindowsCache and staged malicious tools using certutil.exe.
4. Windows Defender exclusions were added for executable, script, and staging paths to evade detection.
5. Persistence was established through a scheduled task named “Windows Update Check” executing payloads from the staging directory.
6. The attacker communicated with an external C2 server at 78.141.196.6 over ports 8080 and 443.
7. A renamed credential-dumping tool (mm.exe) was executed with the sekurlsa::logonpasswords module to extract credentials from LSASS.
8. Collected data was staged into export-data.zip and exfiltrated to an attacker-controlled Discord webhook using curl.exe.
9. Security event logs were cleared using wevtutil.exe to remove forensic evidence.
10. A new local administrator account named support was created to maintain long-term persistence.
11. The attacker executed a malicious PowerShell script (wupdate.ps1) to automate the attack chain.
12. Lateral movement was performed using stored credentials and Remote Desktop connections to the internal system at 10.1.0.188.

---

## Summary

The investigation confirmed a full attack lifecycle beginning with external credential compromise and remote access, followed by network discovery, defense evasion, persistence, credential theft, data exfiltration, log tampering, and lateral movement. The attacker relied heavily on living-off-the-land techniques and built-in Windows utilities to blend malicious activity with legitimate administrative behavior, resulting in the theft and external exfiltration of sensitive company data.

---

## Response Taken

The compromised endpoint azuki-sl was isolated from the network. The kenji.sato account and the malicious support account were disabled, credentials were reset, and relevant management was notified. Indicators of compromise were documented for further enterprise-wide hunting and containment.
