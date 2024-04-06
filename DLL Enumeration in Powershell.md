Get a list of running processes:
```powershell
Get-Process
```

List all DLLs loaded by a running process:
```powershell
Get-Process chrome | select -ExpandProperty modules | group -Property FileName | select name

```

Find all DLLs loaded by a specific process ID:
```powershell
Get-Process -Id 520 | select -ExpandProperty modules | group -Property FileName | select name
```

Find all processes that loaded a specific DLL:
```powershell
Get-Process | where {$_.Modules -match 'chrome_elf.dll'} | select Id, ProcessName
```

List only the name of processes that loaded a specific DLL:
```powershell
Get-Process | where {$_.Modules -match 'chrome_elf.dll'} | select ProcessName | sort-object -Property ProcessName -Unique
```


https://www.c-sharpcorner.com/blogs/list-of-loaded-and-available-modules-in-powershell