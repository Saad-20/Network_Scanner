#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]

    for element in answered_list:
        print(element[1].psrc)
        print(element[1].hwsrc)
        print("---------------------------------------------------------------------------------------"
              "-------------------------------")
    # print(answered_list.summary())


scan("Put IP here")

# arp_request.show()
# broadcast.show()
# arp_request_broadcast.show()
# print(arp_request_broadcast.summary())
