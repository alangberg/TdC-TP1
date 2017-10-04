#! /usr/bin/python
from scapy.all import *
from math import log
import sys, os

def is_unicast_or_broadcast(pkt):
	if pkt.dst == broadcast_addr:
		return 'broadcast'
	else:
		return 'unicast'

def get_protocol(pkt):
	#If it has a superior layer, return it
	if pkt.payload:
		pkt = pkt.payload
		return pkt.name

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
	
	def __init__(self, symbols, name='S1'):
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
	symbols_info = [(k[0], k[1], str(v), str(-log(v, 2))) for k, v in probabilities.iteritems()]
	symbols_header = "Symbol; Probability; Information\n"
	with open(output_file, 'w') as f:
		#Print header and info of each source symbol
		f.write(symbols_header)
		for i in range(len(symbols_info)):
			si = symbols_info[i]
			f.write("({0}, {1}); {2}; {3}\n".format(si[0], si[1], si[2], si[3]))

		f.write("\n\n") #Separator
		entropy_header = "Entropy; Maximum Entropy\n"
		f.write(entropy_header)
		f.write("{0};{1}".format(str(source.entropy()), str(source.max_entropy())))

def pcap_table_S1(output_file):
	global symbols_S1
	global input_file
	print "Reading input pcap file."
	sniff(prn=analyze_pkt_S1, offline=input_file, count=packets_count, store=0)  #Read pcap file
	print "Done. Creating S1 source."
	source_S1 = Source_S1(symbols_S1)
	print "Done. Dumping source info to {0}_S1.csv".format(output_file)
	#source_S1.print_source_info()
	source_to_csv(output_file + "_S1", source_S1)


invalid_args_error = """ Use: python source_info.py [input_file]=sniffer_output.pcap [outputfile]=source_info [source_type]=1\n
					Example: python source_info.py homeNetwork.pcap homeNetwork 1\n
					Creates homeNetwork_S1.csv with the info from the source created by modelling homeNetwork.pcap as a S1 source.
					"""

symbols_S1 = {}
symbols_S2 = {}
	
if __name__ == "__main__":

	input_file = "sniffer_output.pcap"
	output_file = "source_info"
	source_type = 1

	params_count = len(sys.argv)
	if params_count > 1:
		input_file = sys.argv[1]
		if params_count > 2:
			output_file = sys.argv[2]
			if params_count > 3:
				source_type = int(sys.argv[3])
				if params_count > 4:
					print invalid_args_error

	#Simbolo = < unicast/broadcast, ARP/IP/IPv6/?? >
	packets_count = len(rdpcap(input_file))  #Reads all the packets of the pcap file
	broadcast_addr = 'ff:ff:ff:ff:ff:ff'

	if source_type == 1:
		pcap_table_S1(output_file)
	elif source_type == 2:
		#TODO
		pass
	else:
		print "source_type can only be 1 or 2"
