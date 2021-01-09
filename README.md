# My Notes / Cheatsheet
### Last Updated: 09 Jan 2020
Notes related to Vuln Assmnt/PenTesting 

#### Approach for Linux
> 1. Identify open ports (nmap/autorecon/rustscan), enumerate ports (TCP+UDP) for services.
> 1. Run gobuster/wfuzz and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 
> 1. Run nikto, Have you read the source code ? If its a website look whats running ? 
> 1. Wordpress, Joomla, October, Phpmyadmin, Mantis, Adminer etc.
 > * running tools e.g wpscan or joomscan can help further enumeration.
 > * Try running Hydra with HTTP module for brute forcing.
 > * Cewl can be used to generate a custom wordlist if "/usr/share/wordlists/rockyou.txt" fails. 
> 1. Custom built web normally has:
 > * SQL injection - Authentication bypass & Database dump & Upload malicious file.
 > * XSS - Alerting messages and getting cookies
 > * LFI - .php?file=/etc/passwd - Try fuzzing it with WFUZZ. Reading LOG files to acheive RCE or Reading SSH key files.
 > * PHP assert ftn to bypass - e.g. http://192.168.10.30/index.php?page=' and die(system("ls")) or '	
 > * Command Injection - Try Special characters e.g. “ ; , | , & , && ” etc. ${IFS} is space --- Can help in achieving ComInj. 

 

#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.\
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080
