wrap_nfqueue
============

Simple tool to allow for tcpwrapping of services with iptables.

Usage:

wrap_nfqueue QUEUENUMBER PORT DAEMONNAME

Actual usage: wrap_nfqueue 0 443 tlwebaccess

This goes with a rule like
 
iptables -A INPUT -p tcp -m tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -j NFQUEUE --queue-num 0 

Building:

libmnl, libnetfilter and libnetlink are required for building.

On Ubuntu, 

sudo apt-get install libmnl-dev libnfnetlink-dev

For RHEL6 and derivates (and earlier), packages are not available AFAIK.

