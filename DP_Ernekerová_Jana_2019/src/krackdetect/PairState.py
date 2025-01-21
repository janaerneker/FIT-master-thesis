#!/usr/bin/env python2
#
# detection of key reinstallation attacks
# Copyright (c) 2018, Jana Ernekerova <ernekjan@fit.cvut.cz>
#

from Logger import *
from scapy.layers.dot11 import *
from Util import *


class PairState:
    """ Stores data about a pair of a client and an AP """
    def __init__(self, macaddrClient, macaddrAP, p, msgNum = 1):
        self.macaddrClient = macaddrClient
        self.macaddrAP = macaddrAP
        self.reset(True)
        self.eapol_packets = []
        self.last_packet = p
        self.used_s_nonce = []
        self.current_s_nonce = None
        self.current_a_nonce = None
        self.current_a_nonce_replay = 0
        self.packet_number = 0
        self.handle_msg(msgNum, p)

    def reset(self, initial):
        """ Resets into initial value """
        self.ANonces = []

    def handle_msg(self, msgNum, p):
        """ Handles data in EAPOL frames """
        self.eapol_packets.append(p)
        self.last_packet = p
        # p[Dot11QoS].
        if msgNum == 1:
            self.current_a_nonce_replay = 0
            self.current_a_nonce = None
        if msgNum == 2:
            nonce = str(p[EAPOL])[17:49]
            if self.current_s_nonce:
                self.used_s_nonce.append(self.current_s_nonce)
            self.current_s_nonce = nonce
            self.current_a_nonce_replay = 0
            self.current_a_nonce = None
            log(INFO, "Generated SNonce %s" % nonce.encode('hex'))
        if msgNum == 3:
            nonce = str(p[EAPOL])[17:49]
            replay = get_eapol_replay_number(p)
            # print(nonce.encode('hex'))
            # if already known nonce is reused -> client might be under attack
            if (nonce in self.ANonces and self.current_a_nonce and nonce != self.current_a_nonce) \
                    or (nonce == self.current_a_nonce and replay < self.current_a_nonce_replay):
                log(WARNING, "Client %s might be under KRACK attack!" % (self.macaddrClient), showtime=False)
            else:
                # nonce is not known yet -> save it
                self.ANonces.append(nonce)
                if nonce != self.current_a_nonce:
                    self.current_a_nonce = nonce
            self.current_a_nonce_replay = replay



