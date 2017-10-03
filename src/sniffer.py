#! /usr/bin/python
from scapy.all import *
from math import log
import sys, os

packets_count = 15000
output_file = "sniffer_output.pcap"
timeout = 30 * 60		#30 minutes


params_count = len(sys.argv)
if params_count >= 2:
	packets_count = int(sys.argv[1])
	if params_count >= 3:
		output_file = sys.arg[v2]
		if params_count == 4:
			timeout = int(sys.argv[3])
	if params_count > 4:
		print "Use: sudo python sniffer.py [packets count]=15000 [output file]=sniff_output.pcap [timeout]=30min "


#pkts = sniff(filter='arp', store=1, count=packets_count, timeout=timeout) Agarra solo los ARP
pkts = sniff(store=1, count=packets_count, timeout=timeout)
wrpcap(output_file, pkts)
pkts.summary()