#! /usr/bin/python
from scapy.all import *
from math import log
from abc import ABCMeta, abstractmethod
import argparse
import sys, os

def is_unicast_or_broadcast(pkt):
	broadcast_addr = 'ff:ff:ff:ff:ff:ff'
	if pkt.dst == broadcast_addr:
		return 'broadcast'
	else:
		return 'unicast'

def get_protocol(pkt):
	#If it has a superior layer, return it
	if pkt.payload:
		pkt = pkt.payload
		return pkt.name

def is_who_has(pkt):
	if ARP in pkt and pkt[ARP].op == 1:
		return True

	return False

#Use closure to pass other arguments than de packet in the prn function of the sniff.
def add_S1_sample(symbols_sample):
	def analyze_pkt_S1(pkt):
		uni_or_broad = is_unicast_or_broadcast(pkt)
		protocol = get_protocol(pkt)
		symbol = (uni_or_broad, protocol)
		symbols_sample[symbol] = symbols_sample.get(symbol, 0.0) + 1.0  #Adds 1 to symbol apparitions count

	return analyze_pkt_S1

def add_S2_sample(symbols_sample):
	#Assumes packets are ARP
	def analyze_pkt_S2(pkt):
		if is_who_has(pkt):
			dstIP = pkt[ARP].pdst #Assume routers sends more who-has than other hosts		
			symbols_sample[dstIP] = symbols_sample.get(dstIP, 0.0) + 1.0  #Adds 1 to symbol apparitions count

	return analyze_pkt_S2

def source_symbol_probabilities(symbols):
	total = sum(symbols.values())
	probabilities = {}
	#Calculate each symbol probability
	for k,v in symbols.iteritems():
		probabilities[k] = v / total

	return probabilities

class Source(object):
	
	def __init__(self, symbols_sample, name='S'):
		self.probabilities = source_symbol_probabilities(symbols_sample)
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

	def symbol_probabilities(self):
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
		
#Dump source info to a csv file, with sep = ";"
def source_to_csv(output_file, source):
	output_file += ".csv"
	probabilities = source.symbol_probabilities()
	#List of tuples with (uni_or_broad, protocol, probability, information)
	#symbols_info = [(k[0], k[1], str(v), str(-log(v, 2))) for k, v in probabilities.iteritems()]
	symbols_info = [(k, str(v), str(-log(v, 2))) for k, v in probabilities.iteritems()]
	symbols_header = "Symbol;Probability;Information;Entropy;Maximum Entropy\n"
	with open(output_file, 'w') as f:
		#Print header and info of each source symbol. First row is different because it has the entropies.
		f.write(symbols_header)
		s0 = symbols_info[0]
		f.write("{0};{1};{2};{3};{4}\n".format(s0[0], s0[1], s0[2], str(source.entropy()), str(source.max_entropy())))

		for i in range(1, len(symbols_info)):
			si = symbols_info[i]
			f.write("{0};{1};{2}\n".format(si[0], si[1], si[2]))

#Read pcap file and model a source of type source_type
def pcap_to_source(input_file, source_type=1):
	symbols_sample = {}
	print "Reading input pcap file."
	if source_type == 1:
		sniff(prn=add_S1_sample(symbols_sample), offline=input_file, count=packets_count, store=0)  #Read pcap file and create S1 sample
	elif source_type == 2:
		sniff(prn=add_S2_sample(symbols_sample), filter='arp', offline=input_file, count=packets_count, store=0)  #Read pcap file and create S2 sample
	else:
		print "Error: source_type can only be 1 or 2"
	
	print "Creating S{0} source.".format(source_type)
	source = Source(symbols_sample)
	return source

def pcap_table(input_file, output_file, source_type):	
	source = pcap_to_source(input_file, source_type)
	print "Dumping source info to {0}_S{1}.csv".format(output_file, source_type)
	source_to_csv(output_file + "_S{0}".format(source_type), source)


invalid_args_error = """ Use: python source_info.py [input_file]=sniffer_output.pcap [outputfile]=source_info [source_type]=1\n
					Example: python source_info.py homeNetwork.pcap homeNetwork 1\n
					Creates homeNetwork_S1.csv with the info from the source created by modelling homeNetwork.pcap as a S1 source.
					"""
	
if __name__ == "__main__":


	parser = argparse.ArgumentParser(description='Analize a pcap file and produce the information table associated with it in csv format.')
	parser.add_argument('-if', '-i', dest='ifile', action='store', default='sniffer_output',
                    help='Optional pcap input file to be analized. Default = sniffer_output.pcap')
	parser.add_argument('-of', '-o', dest='ofile', action='store', default="source_info",
                    help='Optional output file. Default: source_info.')
	parser.add_argument('-st', '-s', dest='st', action='store', type=int, default=1, choices=[1, 2],
                    help='Source type to model with the input file. Must be 1 or 2. Default: 1')

	args = parser.parse_args()

	input_file = args.ifile + ".pcap"
	output_file = args.ofile
	source_type = args.st

	packets_count = len(rdpcap(input_file))  #Reads all the packets of the pcap file
	pcap_table(input_file, output_file, source_type) #Dump source table to csv
	
