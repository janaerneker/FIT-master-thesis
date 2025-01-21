#!/usr/bin/env python2
#
# detection of key reinstallation attacks
# Copyright (c) 2018, Jana Ernekerova <ernekjan@fit.cvut.cz>
#

from Logger import *
from scapy.all import *
from scapy.layers.dot11 import Dot11
import socket
from Util import *


class ListenSocket(L2ListenSocket):
    def __init__(self, dumpfile, iface, **kwargs):
        self.iface = iface
        super(ListenSocket, self).__init__(**kwargs)
        # self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)
        self.pcap = None
        if dumpfile is not None:
            self.pcap = PcapWriter("%s.%s.pcap" % (dumpfile, self.iface), 
                                   append=True, sync=True)
        
    def recv(self, x=MTU):
        p = L2ListenSocket.recv(self, x)
        if self.pcap:
            self.pcap.write(p)
        if p is None or Dot11 not in p:
            return None
        return p[Dot11]
    
    def close(self):
        super(ListenSocket, self).close()
