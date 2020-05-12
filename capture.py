#!/usr/local/bin/python3
print("hello world")
import os
os.system("tshark -i any -w honey.pcap -q " )
from scapy import all
from scapy.all import *

while True:
  os.system("iptables -A OUTPUT -p tcp -o eth0 -sport 1:65535 -tcp-flags RST RST -j DROP")
def packet(pkt):
  if pkt[TCP].flags == 2:
        if (str(pkt[TCP].dport)) == "22":
            print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' + pkt[IP].src)
send(IP(dst = pkt[IP].src, src = pkt[IP].dst) / TCP(dport = pkt[TCP].sport,
  sport = pkt[TCP].dport,
  ack = pkt[TCP].seq + 1, flags = 'SA'))
sniff(iface = "eth0", prn = packet, filter = "tcp[0xd]&18=2", count = 100)
os.system("iptables -D OUTPUT -p tcp -o eth0 -sport 1:65535 -tcp-flags RST RST -j DROP")
def packet(pkt):
  if pkt[TCP].flags == 2:
        if (str(pkt[TCP].dport)) == "445":
            print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' +
      pkt[IP].src)
send(IP(dst = pkt[IP].src, src = pkt[IP].dst) / TCP(dport = pkt[TCP].sport,
  sport = pkt[TCP].dport,
  ack = pkt[TCP].seq + 1, flags = 'SA'))
sniff(iface = "eth0", prn = packet, filter = "tcp[0xd]&18=2", count = 100)
os.system("iptables -D OUTPUT -p tcp -o eth0 -sport 1:65535 -tcp-flags RST RST -j DROP")
