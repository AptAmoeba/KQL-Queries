If you have designated accounts which run obfuscated code, add them in the Exclusion list. Multiple Accounts will be added using this format: ```let AllowedAccts = dynamic(['Acct1', 'Acct2', 'Acct3'])```
Setting this query as an alert will check your environment every 15 minutes for obfuscated powershell executions and send an alert if any are detected, showing the following:
- Time of execution
- Originating device
- Originating account name
- Plaintext command
- Original obfuscated command
-  Total commands run (if multiple; used during output sorting)

-To do: fix the missing "syntax errors" that KQL complains about for Alert formatting for plug-and-play alerts.
```KQL
//Original created by Ben-Jan Pals. Modifications by AptAmoeba: Added exclusion list; column name cleanup; output sorting by impact, then by recency;
//Original Source: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedCommandsExecuted.md
let EncodedList = dynamic(['-encodedcommand', '-enc']); 
// For more results use line below en filter one above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
let TimeFrame = 15m; //h = hours, d = days, m = mins
let AllowedAccts = dynamic(['']);//Account exclusion list
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
| top 50 by Total_Commands desc //Limits output to only the top 50 results. Adjust as necessary.
| sort by Timestamp desc;
```
