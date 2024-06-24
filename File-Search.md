If you want to pull more information from successful returns, have a look at the MS <a href=https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table>KQL DeviceFileEvents</a> documentation and add the desired fields to the *summarize* statement.

<br>Also, if your environment uses a different browser/Email service, you can replace one of the executables below. 

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
