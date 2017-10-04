#! /usr/bin/python
from scapy.all import *
from math import log
import sys, os

input_file = "sniffer_output.pcap"

params_count = len(sys.argv)
if params_count > 1:
	input_file = sys.argv[1]
	if params_count > 2:
		print "Use: python source_info.py [input_file]=sniffer_output.pcap"

#Simbolo = < unicast/broadcast, ARP/IP/IPv6/?? >
packets_count = len(rdpcap(input_file))  #Reads all the packets of the pcap file
broadcast_addr = 'ff:ff:ff:ff:ff:ff'


def is_unicast_or_broadcast(pkt):
	if pkt.dst == broadcast_addr:
		return 'broadcast'
	else:
		return 'unicast'

def get_protocol(pkt):
	if ARP in pkt:
		protocol = 'ARP'
	elif IPv6 in pkt:
		protocol = 'IPv6'
	elif IP in pkt:
		protocol = 'IP'

	return protocol

def analyze_pkt_S1(pkt):
	global symbols_S1
	uni_or_broad = is_unicast_or_broadcast(pkt)
	protocol = get_protocol(pkt)
	symbol = (uni_or_broad, protocol)
	symbols_S1[symbol] = symbols_S1.get(symbol, 0.0) + 1.0  #Adds 1 to symbol apparitions count

def source_symbol_probabilities(symbols):
	total = sum(symbols.values())
	probabilities = {}
	#Calculate each symbol probability
	for k,v in symbols.iteritems():
		probabilities[k] = v / total

	return probabilities

class Source_S1(object):
	
	def __init__(self, symbols, name):
		self.probabilities = source_symbol_probabilities(symbols)
		self.symbols = self.probabilities.keys()
		self.name = name

	def entropy(self):	
		return sum([self.probabilities[s] * -log(self.probabilities[s], 2) for s in self.symbols])

	def max_entropy(self):
		if len(self.symbols) == 0:
			return 0

		return log(len(self.symbols), 2)

	def name(self):
		return self.name

	def probabilities(self):
		return self.probabilities

	def print_probabilities(self):
		print "Source %s symbols probabilities: " %self.name
		print self.probabilities

	def print_symbols(self):
		print "Source %s symbols: " %self.name
		print self.symbols

	def print_source_info(self):
		print "{0}'s info:".format(self.name)
		self.print_probabilities()
		print "{0}'s entropy is: {1}".format(self.name, self.entropy()) 
		print "{0}'s maximum entropy is: {1}".format(self.name, self.max_entropy())
		

symbols_S1 = {}
print "Reading input pcap file."
sniff(prn=analyze_pkt_S1, offline=input_file, count=packets_count, store=0)  #Read pcap file
print "Done. Creating S1 source."
source_S1 = Source_S1(symbols_S1, 'S1')
source_S1.print_source_info()