#!/usr/bin/python

# import all the things!
from scapy.all import *
from time import *
from random import *
import re

interface = "lo"

# connection table
conn_cache = []

# function to check SYN seq number against algorithm (based on epoch)
def is_correct(seqnum):
  t = time()
  # sequence number can be within 5 seconds of current time
  if ((seqnum + 400000000) / 3) < t and ((seqnum + 400000000) / 3) >= (t - 5):
    return True
  else:
    return False

# sniffing loop
def watch_look_listen(pkt):

  # SYN packet handling
  if TCP in pkt and pkt[TCP].dport == 80 and pkt[TCP].flags == 2:
    seqnum = randint(1, 4294967295)
    if is_correct(pkt[TCP].seq):
      # mark connection as having correct SEQ number
      conn_cache.append( {'time': time(), 'src': pkt[IP].src, 'sport': pkt[IP].sport, 'dport': pkt[TCP].dport, 'seqnum': seqnum, 'is_correct': True, 'est': False} )
    else:
      # mark connection as having incorrect SEQ number
      conn_cache.append( {'time': time(), 'src': pkt[IP].src, 'sport': pkt[IP].sport, 'dport': pkt[TCP].dport, 'seqnum': seqnum, 'is_correct': False, 'est': False} )
    # send SYN+ACK in response to SYN
    p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=seqnum, flags="SA")
    send(p)

  # ACK packet handling
  elif TCP in pkt and pkt[TCP].flags in (16, 24, 48):
    for conn in conn_cache:
      # if SYN packet in connection table is older than 10 seconds, forget about it
      if conn['time'] < (time()-10):
        del conn
      # if the connection is established and contains an HTTP GET...
      elif conn['est'] == True and re.search( 'GET \/ HTTP\/1\.1', str(pkt.payload.payload.payload) ):
        if conn['is_correct'] == True:
          print "send secret HTML file"
        else:
          print "send innocuous HTML file"
      # if the connection is not established and the SYN was seen less than 10 seconds ago
      elif (conn['src'] == pkt[IP].src) and (conn['sport'] == pkt[TCP].sport) and (conn['dport'] == pkt[TCP].dport) and (conn['seqnum'] == pkt[TCP].ack-1):
        # mark the connection established in the connection table
        conn['est'] = True
      # RST all other ACK packets
      else:
        seqnum = randint(1, 4294967295)
        p = IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=seqnum, flags="R")
        send(p)

sniff(iface = interface, count = 0, prn = watch_look_listen)
