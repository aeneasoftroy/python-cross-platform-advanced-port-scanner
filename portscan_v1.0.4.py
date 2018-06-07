#!/usr/bin/env python

# CSF-X-NSA PORTSCANNER by Aeneas of Troy of EHVSN/TechKnow
# ---------------------------------------------------------
# Utilizing 7 methods of port scanning all at once:
# CONN, SYN, FIN, X-MAS, NULL, STEALTH, ACK.
# The script also logs all positive scan results to csf-x-nsa-log.txt
# Learn from the comments in the script how each type of scan works.
#
# Requirements: Scapy ('pip install scapy')
#               Requests
#
# Tested on Windows 7, Debian 9.4.0, Kali, ParrotOS and Ubuntu
#
# Usage: python portscan.py target startPort endPort
#  E.g.: python portscan.py 192.168.1.36 1 65535
#    Or: python portscan.py without parameters for manual input
#
#  Note: thanks to the shebang line we can also make this run as an executable: 
#        1. chmod +x portscan.py
#        2. ./portscan.py target startPort endPort

import sys 
import time
import os
import subprocess
import datetime
import getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from timeit import default_timer as timer

# This is the part to validate the presence of required Python packages.
import pkg_resources
from pkg_resources import DistributionNotFound, VersionConflict
dependencies = [
  'Scapy>=2.4.0',
  #'Requests>=2.18',
]
# When a dependency is not found, a DistributionNotFound or VersionConflict will be raised.
pkg_resources.require(dependencies)

def banner():
	print '___________________________________________________________________________'
	print '|CSF-X-NSA|  __________    EHVSN     __   _________   www.TechKnow.one   ___   '
	print '|OYI-|-UTC|  \______   \____________/  |_/   _____/ ____ _____    ____   \  \  '
	print '|NNN-M-LEK|   |     ___/  _ \_  __ \   __\_____  \_/ ___\\\__  \  /    \   \  \\'
	print '|N---A-LA-|   |    |  (  (_) )  | \/|  | /        \  \____/ __ \|   |  \   )  )'
	print '|----S--L-|   |____|   \____/|__|   |__|/_______  /\_____/______/___|  /  /  / '
	print '|-------T-|   Scans port ranges using 7 methods!\/       v1.0        \/  /__/  '

def bannerlogo():
        print ''
        print '  ______   __________________                     ______    ________   _____   '
        print ' /   ___\ /   ____|_   _____/     ___  ___       |   _  \  /   ____/  /  _  \  '
        print '/   /     \____  \ |    __)  ____ \  \/  /  ____ |  | |  \ \____  \  /  /_\  \ '
        print '\   \____ /       \|     \  /___/  >    <  /___/ |  | |  / /       \/   ___   \\'
        print ' \______//________/\___  /        /__/\__\       |__| |_/ /________/\  /   \  /'
        print '                       \/                                            \/     \/ '

def writeLog(target, port, scantype, portstate):
#writeLog also prints the output, one procedure of printing and logging.
	print target + ':' + port + '\t' + scantype + ' ' + portstate
	fopen = open('./csf-x-nsa-log.txt', 'a', 65536)
	fopen.write( str(datetime.now()) + ',' + target + ',' + scantype + ',' + portstate + ',' + str(port) + '\n' )
	fopen.close()

def tcpconnscan(target, port):
#The connection is established by the client sending an acknowledgement ACK and RST flag in the final handshake. 
#If this three-way handshake is completed, then the port on the server is open. The client sends the first handshake
#using the SYN flag and port to connect to the server in a TCP packet. If the server responds with a RST instead of
#a SYN-ACK, then that particular port is closed on the server.
	tcp_connect_scan_resp = sr1(IP(dst=target)/TCP(sport=777,dport=port,flags="S"),verbose=0,timeout=0.2)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		greatestnumber = 73
		#print "Closed"
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=target)/TCP(sport=777,dport=port,flags="AR"),verbose=0,timeout=0.2)
			writeLog(target, str(port), 'CONN', 'OPEN')
			#print '   CONN Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open"
	elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
		greatestnumber = 73
		#print "Closed"

def tcpsynstealthscan(target, port):
#This technique is similar to the TCP connect scan. The client sends a TCP packet with the SYN flag set and the 
#port number to connect to. If the port is open, the server responds with the SYN and ACK flags inside a TCP packet. 
#But this time the client sends a RST flag in a TCP packet and not RST+ACK, which was the case in the TCP connect scan. 
#This technique is used to avoid port scanning detection by firewalls.
#The closed port check is same as that of TCP connect scan. The server responds with an RST flag set inside a TCP packet
#to indicate that the port is closed on the server
	stealth_scan_resp = sr1(IP(dst=target)/TCP(sport=777,dport=port,flags="S"),verbose=0,timeout=0.2)
	if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
		#print 'STEALTH Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Filtered"
		writeLog(target, str(port), 'STEALTH', 'FILTERED')
	elif(stealth_scan_resp.haslayer(TCP)):
		if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=target)/TCP(sport=777,dport=port,flags="R"),verbose=0,timeout=0.2)
			writeLog(str(target), str(port), 'STEALTH', 'OPEN')
			#print 'STEALTH Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open"
#	elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
#		greatestnumber = 73
#		print "Closed"
	elif(stealth_scan_resp.haslayer(ICMP)):
		if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'STEALTH', 'FILTERED')
			#print ' STEALTH Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Filtered"

def finscan(target, port):
#The FIN scan utilizes the FIN flag inside the TCP packet, along with the port number to connect to on the server. If there is no
#response from the server, then the port is open. If the server responds with an RST flag set in the TCP packet for the FIN scan request
#packet, then the port is closed on the server. An ICMP packet with ICMP type 3 and code 1, 2, 3, 9, 10, or 13 in response to the FIN scan
#packet from the client means that the port is filtered and the port state cannot be found.
	fin_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="F"),verbose=0,timeout=0.2)
	if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
		writeLog(target, str(port), 'FIN', 'OPEN or FILTERED')
		#print '    FIN Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open or Filtered"
	elif(fin_scan_resp.haslayer(TCP)):
		if(fin_scan_resp.getlayer(TCP).flags == 0x14):
			greatestnumber = 73
			#print "Closed:" + str(port)
	elif(fin_scan_resp.haslayer(ICMP)):
		if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'FIN', 'FILTERED')
			#print '    FIN Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Filtered"

def nullscan(target, port):
#In a NULL scan, no flag is set inside the TCP packet. The TCP packet is sent along with the port number only to the server. If the server
#sends no response to the NULL scan packet, then that particular port is open. If the server responds with the RST flag set in a TCP packet,
#then the port is closed on the server. An ICMP error of type 3 and code 1, 2, 3, 9, 10, or 13 means the port is filtered on the server.
	null_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags=""),verbose=0,timeout=0.2)
	if (str(type(null_scan_resp))=="<type 'NoneType'>"):
		writeLog(target, str(port), 'NULL', 'OPEN or FILTERED')
		#print '   NULL Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open or Filtered"
	elif(null_scan_resp.haslayer(TCP)):
		if(null_scan_resp.getlayer(TCP).flags == 0x14):
			greatestnumber = 73
			#print "Closed"
	elif(null_scan_resp.haslayer(ICMP)):
		if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'NULL', 'FILTERED')
			#print '   NULL Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Filtered"

def tcpsynscan(target, port):
#This technique is similar to the TCP connect scan. The client sends a TCP packet with the SYN flag set and the port number to connect to. If
#the port is open, the server responds with the SYN and ACK flags inside a TCP packet. 
	tcpsynscan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="S"),verbose=0,timeout=0.2)
	if (str(type(tcpsynscan_resp))=="<type 'NoneType'>"):
		writeLog(target, str(port), 'SYN', 'OPEN or FILTERED')
		#print '    SYN Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open or Filtered"
	elif (tcpsynscan_resp.haslayer(TCP) and (tcpsynscan_resp.getlayer(TCP).flags & 2) ):
		writeLog(target, str(port), 'SYN', 'OPEN')
		#print '    SYN Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open"

def tcpackscan(target, port):
#The TCP ACK scan isn't used to find open or closed ports, it's used to find if a stateful firewall is present on the server. It only tells if the port
#is being filtered or not. A TCP packet with the ACK flag is set with the port number is sent, if the server responds with the RSP flag set inside a TCP
#packet, then the port is unfiltered and a statful firewall is absent. If the server doesn't respond to the TCP ACK packet, or it responds with a TCP
#packet with ICMP type 3 or code 1,2,3,9,10,13 set, then the port if filtered and a stateful firewall is present.
	ack_flag_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="A"),verbose=0,timeout=0.2)
	if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
		writeLog(target, str(port), 'ACK', 'FILTERED')
		#print '    ACK Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Stateful firewall present (Filtered)"
	elif(ack_flag_scan_resp.haslayer(TCP)):
		if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
			greatestnumber = 73
			#print '    ACK Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " No firewall (Unfiltered)"
	elif(ack_flag_scan_resp.haslayer(ICMP)):
		if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'ACK', 'FILTERED')
			#print '    ACK Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Stateful firewall present (Filtered)"

def xmasscan(target, port):
#In the XMAS scan, a TCP packet with the PSH, FIN, and URG flags set, along with the port to connect to, is sent to the server.
# - If the port is open, then there will be no response from the server.
# - If the server responds with the RST flag set inside a TCP packet, the port is closed on the server.
# - If the server responds with the ICMP packet with an ICMP unreachable error type 3 and ICMP code 1, 2, 3, 9, 10, or 13, then the port is filtered and it cannot be inferred from the response whether the port is open or closed.
	start = timer()
	src_port = RandShort()
	#print 'XMAS Port scan:' + str(datetime.now()) + ' Target: ' + target + ':' + str(port)
	#xmas_scan_resp = sr1( IP(dst=target)/TCP(flags="FPU", dport=(startPort,endPort)), verbose=0, timeout=0.2 )
	xmas_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"),verbose=0,timeout=0.2)
	if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
		writeLog(target, str(port), 'XMAS', 'OPEN or FILTERED')
		#print '   XMAS Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Open or Filtered"
	elif(xmas_scan_resp.haslayer(TCP)):
		if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
			greatestnumber = 73
			#print 'XMAS Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Closed"
	elif(xmas_scan_resp.haslayer(ICMP)):
		if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'XMAS', 'FILTERED')
			#print '   XMAS Port scan: ' + str(datetime.now()) + ' Target: ' + target + ':' + str(port) + " Filtered"

def onlinescan(target, port):
	stealth_scan_resp = sr1(IP(dst=target)/TCP(sport=777,dport=port,flags="S"),verbose=0,timeout=0.3)
	if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
		greatestnumber = 73
	elif(stealth_scan_resp.haslayer(TCP)):
		if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=target)/TCP(sport=777,dport=port,flags="R"),verbose=0,timeout=0.3)
			writeLog(str(target), str(port), 'STEALTH', 'OPEN')
#	elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
#		greatestnumber = 73
	elif(stealth_scan_resp.haslayer(ICMP)):
		if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			writeLog(target, str(port), 'STEALTH', 'FILTERED')
			greatestnumber = 73
	tcpsynscan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="S"),verbose=0,timeout=0.3)
	if (str(type(tcpsynscan_resp))=="<type 'NoneType'>"):
		greatestnumber = 73
	elif (tcpsynscan_resp.haslayer(TCP) and (tcpsynscan_resp.getlayer(TCP).flags & 2) ):
		writeLog(target, str(port), 'SYN', 'OPEN')
	tcp_connect_scan_resp = sr1(IP(dst=target)/TCP(sport=777,dport=port,flags="S"),verbose=0,timeout=0.3)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		greatestnumber = 73
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=target)/TCP(sport=777,dport=port,flags="AR"),verbose=0,timeout=0.3)
			writeLog(target, str(port), 'CONN', 'OPEN')
#	elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
#		greatestnumber = 73

def xmasscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			xmasscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def tcpsynscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			tcpsynscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def tcpackscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			tcpackscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def tcpconnscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			tcpconnscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def tcpsynstealthscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			tcpsynstealthscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def finscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			finscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def nullscan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			nullscan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def onlinescan_start(target,startPort,endPort):
	try:
		for port in range(startPort,endPort):
			onlinescan(target, port)
	except KeyboardInterrupt:
		print 'Cancelled'

def helpscreen():
        print '  ______   __________________                     ______    ________   _____   '
        print ' /   ___\ /   ____|_   _____/     ___  ___       |   _  \  /   ____/  /  _  \  '
        print '/   /     \____  \ |    __)  ____ \  \/  /  ____ |  | |  \ \____  \  /  /_\  \ '
        print '\   \____ /       \|     \  /___/  >    <  /___/ |  | |  / /       \/   ___   \\'
        print ' \______//________/\___  /        /__/\__\       |__| |_/ /________/\  /   \  /'
        print '                       \/                                            \/     \/ '
        print '  ___________________________   ____________________________________________   '
        print ' |CSF-X-NSA port scanner v1.0| | Script by Aeneas of Troy of EHVSN/TechKnow |  '
        print " '---------------------------' | Scans specific port ranges using 7 methods |  "
        print "  _____________________________|>------------------------------------------<|  " 
        print ' |Supported modes: conn, syn, fin, x-mas, null, stealth, ack, full or online|  '
        print ' ```|-> Usage: ./portscan.py -t target -s startPort -e endPort -m mode      |  '
        print '    `->  E.g.: ./portscan.py -t 127.0.0.1 -s 1 -e 65535 -m full             |  '
        print '         ___________________________________________________________________|  '

def scanend():
        if os.name == 'nt':
                wait = input("PRESS ENTER TO CONTINUE.")

def main(argv):
   params = len(sys.argv)
   if params < 2:
       helpscreen()
       print '\n    ERROR: Not enough arguments provided! Manual input required:\n'
       ip = raw_input('Enter target IP [default:127.0.0.1]:') or '127.0.0.1'
       startPort = int(raw_input('Enter port range start [default:1]: ') or int('1'))
       endPort = int(raw_input('Enter port range end [default:65535]: ') or int('65535'))
       mode = raw_input('Enter mode [default:full]:') or 'full'
       self = sys.argv[0]
       my_env = os.environ
       currentdir = os.getcwd()
       print 'OS.NAME = ' + os.name
       if os.name == 'nt':
               my_env["PATH"] = 'C:\Python27;' + my_env["PATH"] 
               execute =  'python ' + self + ' ' + '-t ' + ip + ' -s ' + str(startPort) + ' -e ' + str(endPort) + ' -m ' + mode + ' -exitpause true'
               print 'ENVPATH = ' + my_env["PATH"]
               print 'Starting SubProcess: ' + execute
               subprocess.Popen(execute, env=my_env)
       elif os.name == 'posix':
               my_env["PATH"] = '/usr/bin:/usr/sbin:/sbin:' + my_env["PATH"]
               execute =  'python ' + self + ' ' + '-t ' + ip + ' -s ' + str(startPort) + ' -e ' + str(endPort) + ' -m ' + mode
               print 'ENVPATH = ' + my_env["PATH"]
               print 'Starting SubProcess: ' + execute
               subprocess.Popen(execute, shell=True, env=my_env)
   try:
      opts, args = getopt.getopt(argv,'h:t:s:e:m:',['target=,startPort=,endPort=,mode='])
   except getopt.GetoptError:
      helpscreen()
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         helpscreen()
         sys.exit()
      elif opt in ('-t', '--target'):
         target = arg
         bannerlogo()
         print '   ___...---===[ CSF-x-NSA Portscanner started: ' + str(datetime.now().time()) + ' ]===---...___' + '\n   ' + 74 * '-'
         print '   Target=' + target
      elif opt in ('-s', '--startPort'):
         startPort = arg
         print 'startPort=' + startPort
      elif opt in ('-e', '--endPort'):
         endPort = arg
         print '  endPort=' + endPort
      elif opt in ('-exitpause', '--exitpause'):
         exitpause = arg
      elif opt in ('-m', '--mode'):
         mode = arg
         print '     Mode=' + mode
         if mode == 'full':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'FULL SCAN: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	tcpsynstealthscan_start(target, int(startPort), int(endPort))
         	tcpconnscan_start(target, int(startPort), int(endPort))
         	tcpsynscan_start(target, int(startPort), int(endPort))
         	tcpackscan_start(target, int(startPort), int(endPort))
         	finscan_start(target, int(startPort), int(endPort))
         	nullscan_start(target, int(startPort), int(endPort))
         	xmasscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'stealth':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'Stealth scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	tcpsynstealthscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'conn':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'TCP CONN scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	tcpconnscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'syn':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'TCP SYN scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	tcpsynscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'ack':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'TCP ACK scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	tcpackscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'fin':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'FIN scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	finscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'null':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'NULL scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	nullscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'x-mas':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'X-MAS Nastygram Kamikaze scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	xmasscan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()
         elif mode == 'online':
         	banner()
         	print '|-------H-|' + '                                      Target: ' + target + ':' + str(startPort) + '-' + str(endPort)
         	print 'Online host scanning: ' + target + ':' + startPort + '-' + endPort
         	start = timer()
         	onlinescan_start(target, int(startPort), int(endPort))
         	end = timer()
         	print '\nScan duration: ' + str(end - start) + ' seconds\n'
         	scanend()

if __name__ == "__main__":
	main(sys.argv[1:])
