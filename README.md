# KQL-Queries
A collection of custom KQL Queries that I've written for 365 Defender's 'Advanced Threat Hunting.'
<br>
If you'd like more verbose info/usage help on each query, check the actual files above. 

## List
### Pull user/device downloads
```KQL
// Created by AptAmoeba
// Query to pull the downloads of a target user or device.
DeviceFileEvents 
| where Timestamp > ago(1d)
// Below statements: Change "==" to "contains" for fuzzysearch.
| where InitiatingProcessAccountName == 
    "user" // Target user
//| where DeviceName contains 
//    "deviceName" // Target device
| where 
    InitiatingProcessFileName in~ ("msedge.exe", "outlook.exe", "chrome.exe")
| where FolderPath !contains "\\AppData"
| summarize arg_max(Timestamp, User=InitiatingProcessAccountName, Device=DeviceName, Path=FolderPath, Downloaded_using=InitiatingProcessFileName, SHA256) by FileName
| top 50 by Timestamp desc;
```

&nbsp;

### Search what users have a certain file
```KQL
// Created by AptAmoeba
// Query to locate which users downloaded a file.
DeviceFileEvents 
| where Timestamp > ago(5d)
// Below statement: Change "==" to "contains" for fuzzysearch.
| where FileName == 
    "filename.pdf" // Target file (Include extension) 
| where 
    InitiatingProcessFileName in~ ("msedge.exe", "outlook.exe", "chrome.exe")
| summarize arg_max(Timestamp, User=InitiatingProcessAccountName, Device=DeviceName, Downloaded_using=InitiatingProcessFileName, Path=FolderPath, SHA256) by FileName
| sort by Timestamp desc; //[alternative for high-yield files]: | top 50 desc;
```
