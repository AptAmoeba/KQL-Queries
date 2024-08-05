This will likely require some tuning before you deploy it as an alert. 
- Customization example: If you have developers, Git can use SSH. So, you'd add git.exe to the AppWhitelist and then uncomment the File Whitelist line in the lower section.
  - You can get more granular by combining the App & User whitelists to create ringfencing, where only certian users are excluded in the detection output for certain applications.

```KQL
//Created by AptAmoeba - SSH Execution Detected on Endpoint
let UserWhitelist = dynamic(['']);//Account whitelist
let AppWhitelist = dynamic(['']);//File whitelist
let ExecWhitelist = dynamic(['']);//Executed command whitelist
DeviceProcessEvents
| where Timestamp > ago(1d) and Timestamp > ago(1h)
| where FileName in~ ("ssh.exe")
    or InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe", "git.exe") and InitiatingProcessCommandLine contains "ssh"
    or InitiatingProcessFileName in~ ("plink.exe", "putty.exe")
//| where not(InitiatingProcessAccountName in (UserWhitelist)) //Exclude Account whitelist items
//| where not(InitiatingProcessFileName in (AppWhitelist)) //Exclude File whitelist items
//| where not(ProcessCommandLine has_any (ExecWhitelist)) //Exclude Executions whitelist items
| project Timestamp, User=InitiatingProcessAccountName, Executed_Command=ProcessCommandLine, Process=InitiatingProcessFileName, wasProcRemote=IsProcessRemoteSession, wasInitProcRemote=IsInitiatingProcessRemoteSession, DeviceId, ReportId
| top 50 by Timestamp desc
```
