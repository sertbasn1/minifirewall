# minifirewall

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
