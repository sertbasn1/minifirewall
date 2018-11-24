import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
import binascii


a=IP(dst="192.168.56.101")/TCP(sport=2000)/binascii.unhexlify('62626c6120626c1D612068656c6c6f20651F7463')
hexdump(a)

b=IP(dst="192.168.56.101")/UDP(sport=2000)/binascii.unhexlify('68656c6c6f2066721f6f6d15207475726b657920efbfbd68656c6c6f')
hexdump(b)


send(a)
send(b)


