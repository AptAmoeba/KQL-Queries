Comment out either of the following based on how you want to search (default is Username Search):
- Lines 6-7: Username Search
- Lines 7-8: Device Search

If you want to pull more information from successful returns, have a look at the MS <a href=https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table>KQL DeviceFileEvents</a> documentation and add the desired fields to the *summarize* statement.

<br>Also, if your environment uses a different browser, you can replace one of the browser executables below. 
```KQL
// Created by AptAmoeba
// Query to search the downloads of a target user or device.
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
