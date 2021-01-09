# My Notes / Cheatsheet
### Last Updated: 09 Jan 2020
Notes related to Vuln Assmnt/PenTesting 

#### Approach for Linux
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
> 1. Creds file or any misconfiguration file? (**find** command)
> 1. SUDO commands this user can run ?
> 1. SUID binaries present (use **find** command or **suid3num python** script)
> 1. Is there SQL database, try enumerating it ?
> 1. Running ports / services on this box ? (use **netstat** or **ss** command)
> 1. Pspy ?
> 1. Kernel or other exploits e.g. exploits for SUDO ?
> 1. **Linpeas** or **LinEnum** or **Linux Exploit Suggester**


#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.\
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080
