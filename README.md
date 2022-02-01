# ARP_Spoof_Detect
Scans for Duplicate MAC and IP addresses on a network.
For use with Python 3 in Linux.
Requires: Scapy, ArgParse, Time, and Sys.
Input format: python3 arp_spoof_detect.py -t target ip -i scan interval (seconds) -e MAC address to exclude (optional)
Input example: python3 arp_spoof_detect.py -t 111.11.111.1/24 -i 15 -e 00:11:22:33:44:55
