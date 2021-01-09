# My Notes / Cheatsheet
### *Last Updated: 24 Dec 2020*
Notes related to Vuln Assmnt/PenTesting 

#### Approach Linux
> 1. Identify open ports (nmap/autorecon/rustscan), enumerate ports (TCP+UDP) for services.
> 2. Run gobuster/wfuzz and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 

#### Portforwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080
