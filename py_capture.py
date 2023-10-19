import pcapy
import dpkt
import fnmatch
import test
from test import TASKSTATE
from math import floor 
from enum import Enum
fin_processed = False
from scapy.all import *
import multiprocessing as mp

"""
    ip + port determines one stream.
    SEQUENCE determines the current state.
    state: 1. handshake phase,  2. data phase.
    1 -> 2 and 2 -> 1 is ok.
"""

def start():
    dev = fnmatch.filter(pcapy.findalldevs(), "lo*")
    print("listening on interface " + dev[0])
    p = pcapy.open_live(dev[0], 65536, False, 1)

    mp.Process(target = worker, daemon = True).start()
    p.loop(-1, sender)

queue = mp.Queue()

def worker():
    scheduler = Scheduler()
    while True:
        data = queue.get()
        scheduler.run(None, data)

def sender(_, data):
    queue.put(data)

class Task:
    def __init__(self, handler):
        self.seq = 1
        self.handler = handler 

    def increase(self):
        # one cyple represents 1 seq num.
        self.seq += 0.5

    def get_seq(self):
        # seq num is 64 bits long.
        return floor(self.seq)

class Scheduler:
    # ip:port pair to determine the task.
    def __init__(self):
        self.tasks = {}

    def run(self, header, data):
        # parse ip & port.
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        tcp = ip.data
        if len(tcp.data) <= 0:
            return False

        """
        same stream: src <-> dst exchangable.
        binding scheme -> src:sport <=> dst:dport
        """
        src, dst = str(ip.src), str(ip.dst)
        sport, dport = str(tcp.sport), str(tcp.dport)
        src_id = src+":"+sport
        dst_id = dst+":"+dport

        # set is unordered and frozenset makes it hashable.
        pair_set = frozenset({src_id, dst_id})

        if pair_set in self.tasks:
            task = self.tasks[pair_set]
        else:
            handler = test.PktHandler()
            self.tasks[pair_set] = Task(handler) 
            task = self.tasks[pair_set]

        seq = task.get_seq()
        while True:
            (state, isdhe) = task.handler.handle_packet(header, bytes(tcp), seq)

            if state == TASKSTATE.KILL.value:
                del self.tasks[pair_set]
            elif state == TASKSTATE.COMMUNICATION.value: 
                task.increase()
            """
            elif state == TASKSTATE.RESTART.value:
                handler = test.PktHandler()
                self.tasks[pair_set] = Task(handler) 
                continue
            """
            return

if __name__ == "__main__":
    start()

