# minifirewall

--------------------------------------------
REQUIREMENTS

libnfnetlink Library

  - https://www.netfilter.org/projects/libnfnetlink/

libnetfilter_queue library

  - https://netfilter.org/projects/libnetfilter_queue/

Scapy: Packet crafting for Python2 and Python3

  - https://scapy.net

Implementation requires at least Linux kernel 3.6

--------------------------------------------

Step 1: (On the main host that firewall is enabled)

Compile and run cap.c with root privillages as follows:

How to compile:
gcc -Wall -o cap cap.c -lnfnetlink -lnetfilter_queue

How to run: example
sudo ./cap 192.168.56.102 2000 3 hello

--------------------------------------------

Step 2: (On any other external host)

Start the traffic with following Scapy code:

sudo python sendPck.py

--------------------------------------------

Step 3: Check the output.txt file for results

--------------------------------------------
