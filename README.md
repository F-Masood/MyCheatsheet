# My Notes / Cheatsheet
### Last Updated: 09 Jan 2020
Notes related to Vuln Assmnt/PenTesting 

#### Approach Linux
> 1. Identify open ports (nmap/autorecon/rustscan), enumerate ports (TCP+UDP) for services.
> 1. Run gobuster/wfuzz and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 
> 1. Run nikto, Have you read the source code ? If its a website look whats running ? 
> 1. Wordpress, Joomla, October, Phpmyadmin, Mantis, Adminer etc.
    * 1. running tools e.g wpscan or joomscan can help further enumeration.
    * 1. Try running Hydra with HTTP module for brute forcing.
    * 1. Cewl can be used to generate a custom wordlist if "/usr/share/wordlists/rockyou.txt" fails. 
 

#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080
