#!/usr/bin/env python
import scapy.all as scapy
from pip._vendor.distlib.compat import raw_input

# Defining the scan function
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    response_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Creating list of clients in a dictonary and calling them out using the key of each dictionary via list
    clients_list = []
    for element in response_list:
        # print ip address + print MAC address
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

# Will return the results of each client stored in the client list
def print_result(results_list):
    print("--------------------------------------------")
    print("|\tIP\t\t    MAC Address\t   |\n--------------------------------------------")

    for client in results_list:
        print(client['ip'] + "\t\t" + client['mac'])

read_scan_ip = raw_input("[+] Enter ip address to scan: ")
scan_result = scan(read_scan_ip)
print_result(scan_result)



# arp_request.show()
# broadcast.show()
# arp_request_broadcast.show()
# print(arp_request_broadcast.summary())
# print(answered_list.summary())
# print(element[1].psrc + "\t\t\t\t" + element[1].hwsrc)
# print("---------------------------------------------")
