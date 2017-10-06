#! /usr/bin/python
from scapy.all import *
from math import log
import argparse
import sys, os


if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='Sniff network and save captured packets into pcap file. Warning: Requires permissions, i.e. sudo!')
	parser.add_argument('-pc', '-p', dest='pc', action='store', type=int, default=15000,
	                help='Amount of packets to sniff. Default = 15000')
	parser.add_argument('-of', '-o', dest='ofile', action='store', default="sniffer_output",
	                help='Optional output file. Default: sniffer_output.')
	parser.add_argument('-to', '-t', dest='to', action='store', type=int, default=60*60,
	                help='Timeout time in seconds for the sniffing. Default: 1 hour')
	parser.add_argument('-sm', '-s', dest='sm', action='store_true', help='Show captured packets summary in sys.stdout')

	args = parser.parse_args()
	packets_count = args.pc
	output_file = args.ofile + ".pcap"
	timeout = args.to
	show_summary = args.sm

	pkts = sniff(store=1, count=packets_count, timeout=timeout)
	wrpcap(output_file, pkts)
	if show_summary:
		pkts.summary()