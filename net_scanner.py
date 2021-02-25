#! /usr/bin/Python

import sys
from time import sleep
from datetime import datetime
import scapy.all as scapy
import argparse
from scapy.layers.inet import IP,ICMP

print('''
     __     _       __                                 
  /\ \ \___| |_    / _\ ___ __ _ _ __  _ __   ___ _ __ 
 /  \/ / _ \ __|   \ \ / __/ _` | '_ \| '_ \ / _ \ '__|
/ /\  /  __/ |_    _\ \ (_| (_| | | | | | | |  __/ |   
\_\ \/ \___|\__|___\__/\___\__,_|_| |_|_| |_|\___|_|   
              |_____|   By : Abdul_Samad                                
''')
print("-" * 55 + "\n" + "Time started at : " + str(datetime.now()))
print("[+] Note: The accuracy of Detecting O.S is 80% correct... \n")
words = "Scanning....Please Wait!"
for char in words:
    sleep(0.15)
    sys.stdout.write(char)
    sys.stdout.flush()
print("\n")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target-Ip/IP-Range")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify the Target Ip / IP-Range")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_request
    ans_lst = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in ans_lst:
        pack = IP(dst=element[1].psrc)/ICMP()
        resp = scapy.sr1(pack, timeout=30, verbose=False)
        if resp == None:
            print("No response")
        elif IP in resp:
            if resp.getlayer(IP).ttl <= 64:
                os = "linux"
            else:
                os = "windows"
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc, "os" : os}
        clients_list.append(client_dict)
    return clients_list

def print_rslt(result_list):
    print("\n" + "IP" + "\t\t\t" + "MAC Address" + "\t\t" + "OS" + "\n" + "-" * 55)
    for clients in result_list:
        print(clients["ip"] + "\t\t" + clients["mac"] + "\t" + clients["os"])

options = get_args()
scan_result = scan(options.target)
print_rslt(scan_result)
