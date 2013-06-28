#!/usr/bin/python

from time import *
from scapy.all import *

# set current time as integer
t = int( time.time() )

# INCORRECT sequence number generation algorithm
s = ((t * 3) - 411111111)

# SYN packet set with INCORRECTLY seeded sequence number
syn = IP(dst="192.168.1.102")/TCP(dport=80, seq=s, flags="S")

# send SYN, receive SYN+ACK
sa = srp1( Ether() / syn, iface = "lo" )

# generate final ACK of handshake
ack = IP(dst=sa[IP].src) / TCP(dport=sa[TCP].sport, sport=sa[TCP].dport, seq=sa[TCP].ack, ack=sa[TCP].seq+1, flags="A")
send(ack)

# send a sort of GET request
g = IP(dst=sa[IP].src) / TCP(dport=sa[TCP].sport, sport=sa[TCP].dport, seq=sa[TCP].ack, ack=sa[TCP].seq+1, flags="PA") / Raw(load="GET / HTTP/1.1")
send(g)
