#! /usr/bin/python
from scapy.all import *
from math import log
import sys, os

input_file = "sniffer_output.pcap"
packets_count = 15000

params_count = len(sys.argv)
if params_count > 1:
	input_file = sys.argv[1]
	if params_count > 2:
		packets_count = sys.argv[2]
	if params_count > 3:
		print "Use: python source_info.py [input_file]=sniffer_output.pcap [packet count]=15000"

#Simbolo = < unicast/broadcast, ARP/IP/IPv6/?? >

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
	global source
	uni_or_broad = is_unicast_or_broadcast(pkt)
	protocol = get_protocol(pkt)
	symbol = (uni_or_broad, protocol)
	source[symbol] = source.get(symbol, 0.0) + 1.0  #Aumenta 1 la cantidad de apariciones del simbolo

def source_symbol_probabilities(source):
	total = sum(source.values())
	probabilities = {}
	#Calculo la probabilidad de cada simbolo
	for k,v in source.iteritems():
		probabilities[k] = v / float(total)

	return probabilities

def entropy(source):
	probabilities = source_symbol_probabilities(source)
	entropy = 0
	#Calculo la entropia
	print source
	for k in source.keys():
		pk = probabilities[k]
		ik = -log(pk, 2)
		entropy += pk * ik

	return entropy

def max_entropy(source):
	symbols_qty = len(source.keys())
	if symbols_qty == 0:
		return 0

	return log(symbols_qty, 2)


source = {}
print "Leyendo pcap fuente"
sniff(prn=analyze_pkt_S1, offline=input_file, count=packets_count, store=0)  #Leo archivo pcap
print "Termine de leer fuente. Calculando entropia..."
entropy = entropy(source)
print "La entropia de la fuente S1 es: %d" %entropy