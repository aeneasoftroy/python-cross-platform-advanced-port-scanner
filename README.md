# CSF-X-NSA PORTSCANNER 

Cross platform Python 2.7 advanced port scanner, uses 7 techniques of port scanning.

Utilizing 7 methods of port scanning all at once:
CONN, SYN, FIN, X-MAS, NULL, STEALTH, ACK.
The script also logs all positive scan results to csf-x-nsa-log.txt
Learn from the comments in the script how each type of scan works.


Requirements: Scapy ('pip install scapy')
              Requests
              
              
Tested on Windows 7, Debian 9.4.0, Kali, ParrotOS and Ubuntu


    1. Usage: python portscan.py target startPort endPort

    1.  E.g.: python portscan.py 192.168.1.36 1 65535
    1.    Or: python portscan.py without parameters for manual input


Note: thanks to the shebang line we can also make this run as an executable: 

       1. chmod +x portscan.py
       
       2. ./portscan.py target startPort endPort

Aeneas of Troy (EHVSN/TechKnow)
