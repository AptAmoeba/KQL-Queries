# KQL-Queries
A collection of custom KQL Queries that I've written for 365 Defender's 'Advanced Threat Hunting.'
<br>
If you'd like more verbose info/usage help on each query, check the actual files above. 

## List
### Detect & Deobfuscate Base64-Encoded Powershell Commands
```KQL
//Original created by Ben-Jan Pals. Modifications by AptAmoeba: Added exclusion list; column name cleanup; output sorting by impact, then by recency;
//Original Source: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedCommandsExecuted.md
let EncodedList = dynamic(['-encodedcommand', '-enc']); 
// For more results use line below en filter one above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
let TimeFrame = 15m; //h = hours, d = days, m = minutes
let AllowedAccts = dynamic(['system']);//Account exclusion list
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| where not(InitiatingProcessAccountName in (AllowedAccts))
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| summarize Decoded_Commands = make_set(DecodedCommandLineReplaceEmptyPlaces) by DeviceName, InitiatingProcessAccountName, ProcessCommandLine, Timestamp
| extend TotalUniqueEncodedCommandsExecuted = array_length(Decoded_Commands)
| project Timestamp, Device=DeviceName, Account=InitiatingProcessAccountName, Decoded_Commands, Obfuscated_Command=ProcessCommandLine, Total_Commands=TotalUniqueEncodedCommandsExecuted
| top 50 by Total_Commands desc
| sort by Timestamp desc;
```

&nbsp;

### Pull User/Device Downloads
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

### Detect Which Users Have a Specified File
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
