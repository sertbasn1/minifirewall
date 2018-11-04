from scapy.all import *

data = "hello bla bla hello"
a = IP(dst="192.168.56.101")/TCP()/data
send(a)
