# netdisc.py

""" 
Core Network Scanner Module for Network Topology Discovery. 
"""

import os
import socket
from scapy.all import ARP, Ether, srp

class NetworkScanner:
    def __init__(self, subnet):
        self.subnet = subnet
        self.device_list = []

    def scan(self):
        print(f"Scanning subnet: {self.subnet}")

        # Creating ARP request
        arp = ARP(pdst=self.subnet)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp

        # Sending packet and receiving answer
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            self.device_list.append({'ip': received.psrc, 'mac': received.hwsrc})

    def get_devices(self):
        return self.device_list

if __name__ == '__main__':
    subnet = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
    scanner = NetworkScanner(subnet)
    scanner.scan()
    devices = scanner.get_devices()
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")