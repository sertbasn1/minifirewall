import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
data1 = "hello ha ha hello bla"
a = IP(dst="192.168.56.101")/TCP(sport=2000)/data1

data2 = "xyz blah abc"
b = IP(dst="192.168.56.101")/UDP(sport=2000)/data2

data3 = "hello abcc"
c = IP(dst="192.168.56.101")/UDP(sport=2000)/data3




#will only be captured NO MATCH
send(b)
time.sleep(1)

#will be captured and matched
send(c)
time.sleep(1)

#will be captured and matched
send(c)
time.sleep(1)
