# Silentium
## Enumeration
### Nmap
Start with a quick scan
```bash
nmap -sV -T4 <IP> -o nmap-silentium.txt
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Let's add `silentium.htb` to our `/etc/hosts`.
After `fuzzing` for `VHOSTS`, I found a `staging` VHOST, so we also need to add it to our `/etc/hosts`.  
