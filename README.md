# My Notes
Notes related to Vuln Assmnt/PenTesting 


*Portforwarding local service 8080*
>using #socat for local port forwarding. In this example port 8080 is running locally and we will forward and make it public to 8089.
>socat TCP-LISTEN:8089,fork TCP:127.0.0.1:8080
