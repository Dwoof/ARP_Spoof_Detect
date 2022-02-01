import scapy.all as scapy
import argparse
import time
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range (Required).")
    parser.add_argument("-i", "--interval", dest="interval", help="Seconds between scans (Required).")
    parser.add_argument("-e", "--exclude", dest="exclude", help="Exclude MAC address entered (optional).")
    options = parser.parse_args()
    return options


def scan(ip, exclusion):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    device_list = []
    for element in answered_list:
        if element[1].hwsrc != exclusion:
            ip_str = element[1].psrc
            device_list.append(ip_str)
            mac_str = element[1].hwsrc
            device_list.append(mac_str)
    return device_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------------------------")
    for device in results_list:
        print(device["ip"] + "\t\t" + device["mac"])


def dup_scan(dup_check):
    dup_check = dup_check
    dup_scan_list = []
    for element in dup_check:
        if element not in dup_scan_list:
            dup_scan_list.append(element)
        else:
            dupe = element
            print("Dupe found: " + dupe, end='')
            print("\n")
            sys.exit()


def main_loop():
    options = get_arguments()
    scan_result = scan(options.target, options.exclude)
    dup_scan(scan_result)


# Program Start #
dupe = False
main_loop()
attempts_count = 0
while not dupe:
    main_loop()
    options = get_arguments()
    pause_time = options.interval
    attempts_count = attempts_count + 1
    print("\r[+] Scan Count: " + str(attempts_count) +
          ". Waiting " + str(pause_time) + " seconds to re-scan...", end="")
    time.sleep(int(pause_time))







