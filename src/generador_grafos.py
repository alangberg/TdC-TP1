from scapy.all import *
import argparse
import sys, os
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
    
ips = {} #clave= src, significado = lista de destinatarios
def pcap_to_graph(input_file):
    print "Reading input pcap file."
    sniff(prn=gather_data, filter='arp',count = packets_count, offline=input_file, store=0)
    build_and_plot_graph()


def build_and_plot_graph():
    print "building graph"
    DG= nx.Graph()
    for (src, dsts) in ips.items():
    	for dst in dsts:
   	        DG.add_edge(src, dst)
    degrees = DG.degree()
    nodes = DG.nodes()
    n_color = np.asarray([degrees[n] for n in nodes])
    print "plotting graph"
    nx.draw(DG,node_size=n_color+50, node_color = n_color,cmap=plt.cm.Blues, with_labels=False ,pos=nx.spring_layout(DG))
    plt.savefig(input_file[:len(input_file)-5] + ".eps", format='eps', dpi =1000)
    plt.show()


def gather_data(pkt):
    global ips
    if ARP in pkt and pkt[ARP].op == 1: #who-has 
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        dstsBySrc = ips.get(src, [])
        if dst not in dstsBySrc:
        	ips[src] = dstsBySrc + [dst]

if __name__ == "__main__":


    parser = argparse.ArgumentParser(description='Analize a pcap file and produce the information table associated with it in csv format.')
    parser.add_argument('-if', '-i', dest='ifile', action='store', default='sniffer_output_meli',
                    help='Optional pcap input file to be analized. Default = sniffer_output.pcap')
    args = parser.parse_args()

    input_file = args.ifile + ".pcap"
    packets_count = len(rdpcap(input_file))
    pcap_to_graph(input_file)
    
