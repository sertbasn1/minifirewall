import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
data1 = "hello bla bla hello bla"
a = IP(dst="192.168.56.101")/TCP(sport=2000)/data1

data2 = "blah blah blah abc"
b = IP(dst="192.168.56.101")/TCP(sport=2000)/data2


i=0
for i in range(0,4):
	send(a)
	send(b)
	i=i+1

