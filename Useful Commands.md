## find

SUID/SGID files :
```sh
# Find SGID files :
find / -perm /2000 -exec ls -ls {} \; 2>/dev/null

# Find SUID files :
find / -perm /4000 -exec ls -ls {} \; 2>/dev/null

# Find both SGID and SUID :
find / -perm /6000 -exec ls -ls {} \; 2>/dev/null
```


## Network information 

Ping sweep /24 :
```sh
for i in $(seq 254); do ping 172.16.139.$i -c1 -W1 & done | grep from
```


Search for NFS Shares:
```sh
showmount -e  10.10.0.10
```
Mount NFS share :
```bash
sudo mount -t nfs 10.10.0.10:/backups /var/backups
```
