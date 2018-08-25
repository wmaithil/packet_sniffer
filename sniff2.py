from scapy.all import *

def sniffer(packet):
	if(packet[IP].dport==80):
		print("\n{}-----HTTP-----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst ,packet[IP].dport, str(bytes(packet[TCP].payload))))

sniff(filter='tcp port 80',prn=sniffer)
