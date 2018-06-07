# CSF-X-NSA PORTSCANNER 

Cross platform Python 2.7 advanced port scanner, uses 7 techniques of port scanning.

Utilizing 7 methods of port scanning all at once:
**CONN, SYN, FIN, X-MAS, NULL, STEALTH, ACK.**
The script also logs all positive scan results to csf-x-nsa-log.txt
Learn from the comments in the script how each type of scan works.


### Requirements: 
       1. Scapy ('pip install scapy')
       2. Requests
            
              
### Tested on: 

    1. Windows 7
    2. Debian 9.4.0
    3. Kali
    4. ParrotOS
    5. Ubuntu


### Usage: python portscan.py target startPort endPort


      E.g.: python portscan.py 192.168.1.36 1 65535
      
        Or: python portscan.py without parameters for manual input


Note: thanks to the shebang line we can also make this run as an executable: 

       1. chmod +x portscan.py
       
       2. ./portscan.py target startPort endPort

Aeneas of Troy (EHVSN/TechKnow)
