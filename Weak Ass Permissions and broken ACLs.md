## Weak service permissions

We can use SharpUp to look for weak permissions on services.
[SharpUp](https://github.com/GhostPack/SharpUp/) is a port of PowerUp in C#, it's part of GhostPack, a god tier collection of tools for AD pentesting.

Here for example it found vulnerable services i can exploit :
```
PS C:\Tools> .\SharpUp.exe

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Services ===

  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"


=== AlwaysInstallElevated Registry Keys ===

[ETC....]
```

We could simply replace `C:\Program Files (x86)\Windscribe\WindscribeService.exe` by a malicious executable, like a reverse shell generated using msfvenom, then start the service using `sc start SecurityService`

Check my notes on the Server Operators security group for more details on this specific attack.
## Unquoted service path 

Searching for unquoted service paths :
(Run in cmd.exe, not powershell because it's weird with quotes) 
```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
When a path is unquoted we can hijack it if we can place an executable in the partial path, like, for example : 

For the path C:\Program Files (x86)\Windscribe\WindscribeService.exe <br>
if we create C:\Program.exe
 it will be run with the service o/
## Permissive registry ACLs

We can use acesschk to look for weak permissions on registry entries :
```
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```
## Check for autorun

More info on autoruns [here](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)

```ps1
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```